//! Run output: human-readable step lines and summary, JUnit XML, and JSON.
//! Reports only contain redacted assertion messages and never response bodies.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::assertions::AssertionResult;
use crate::runner::{RunReport, Status, StepResult};
use crate::view::Paint;

/// Report formats for `--report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// JUnit XML.
    Junit,
    /// JSON.
    Json,
}

/// Parses `junit=path` or `json=path`.
pub fn parse_spec(spec: &str) -> Result<(Format, PathBuf)> {
    let Some((kind, path)) = spec.split_once('=') else {
        bail!("--report needs FORMAT=PATH, e.g. junit=out.xml")
    };
    let format = match kind {
        "junit" => Format::Junit,
        "json" => Format::Json,
        other => bail!("unknown report format `{other}` (use junit or json)"),
    };
    if path.is_empty() {
        bail!("--report {kind}= needs a path");
    }
    Ok((format, PathBuf::from(path)))
}

/// Renders a report in `format`.
pub fn render(report: &RunReport, format: Format) -> Result<String> {
    Ok(match format {
        Format::Junit => junit(report),
        Format::Json => serde_json::to_string_pretty(report)? + "\n",
    })
}

/// One line per check, indented.
pub fn assertion_lines(assertions: &[AssertionResult], p: Paint, only_failures: bool) -> String {
    let mut out = String::new();
    for a in assertions.iter().filter(|a| !only_failures || !a.passed) {
        let mark = if a.passed {
            p.green("✓")
        } else {
            p.red("✗")
        };
        let detail = a
            .message
            .as_deref()
            .map(|m| format!(": {m}"))
            .unwrap_or_default();
        let _ = writeln!(out, "    {mark} {}{}", a.name, p.dim(&detail));
    }
    out
}

/// A compact line for a step plus its failures (or all checks when `verbose`).
pub fn step_line(r: &StepResult, p: Paint, show_iteration: bool, verbose: bool) -> String {
    let mark = match r.status {
        Status::Passed => p.green("✓"),
        Status::Failed => p.red("✗"),
        Status::Error => p.red("!"),
        Status::Skipped => p.dim("-"),
    };
    let iter = if show_iteration {
        p.dim(&format!("[{}] ", r.iteration))
    } else {
        String::new()
    };
    let grpc = r.file.ends_with(".grpc");
    let status = r
        .http_status
        .map(|s| {
            if grpc {
                p.status(if s == 0 { 200 } else { 500 }, crate::grpc::code_name(s))
            } else {
                p.status(s, &s.to_string())
            }
        })
        .unwrap_or_else(|| p.dim("---"));
    let time = if r.status == Status::Skipped {
        "skipped".into()
    } else {
        format!("{:.1} ms", r.time_ms)
    };
    let mut out = format!("{mark} {iter}{}  {status}  {}\n", r.file, p.dim(&time));
    if let Some(e) = &r.error {
        for line in e.lines() {
            let _ = writeln!(out, "    {}", p.red(line));
        }
    }
    out.push_str(&assertion_lines(&r.assertions, p, !verbose));
    out
}

/// One-line summary.
pub fn summary_line(report: &RunReport, p: Paint) -> String {
    let s = &report.summary;
    let iters = if s.iterations > 1 {
        format!(" across {} iterations", s.iterations)
    } else {
        String::new()
    };
    let mut parts = vec![p.green(&format!("{} passed", s.passed))];
    if s.failed > 0 {
        parts.push(p.red(&format!("{} failed", s.failed)));
    }
    if s.errors > 0 {
        parts.push(p.red(&format!("{} errors", s.errors)));
    }
    if s.skipped > 0 {
        parts.push(p.yellow(&format!("{} skipped", s.skipped)));
    }
    let checks: usize = report.results.iter().map(|r| r.assertions.len()).sum();
    format!(
        "{} requests{iters}: {} ({checks} checks) in {:.2} s\n",
        s.total,
        parts.join(", "),
        s.duration_ms / 1000.0
    )
}

/// Escapes text for XML attributes and content.
fn xml_escape(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// JUnit XML with one `<testsuite>` per iteration.
pub fn junit(report: &RunReport) -> String {
    let s = &report.summary;
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<testsuites name=\"curly\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{:.3}\">",
        s.total,
        s.failed,
        s.errors,
        s.skipped,
        s.duration_ms / 1000.0
    );
    for iteration in 1..=s.iterations.max(1) {
        let cases: Vec<&StepResult> = report
            .results
            .iter()
            .filter(|r| r.iteration == iteration)
            .collect();
        let count = |st: Status| cases.iter().filter(|r| r.status == st).count();
        let time: f64 = cases.iter().map(|r| r.time_ms).sum::<f64>() / 1000.0;
        let name = if s.iterations > 1 {
            format!("curly iteration {iteration}")
        } else {
            "curly".into()
        };
        let _ = writeln!(
            out,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{time:.3}\"{}>",
            xml_escape(&name),
            cases.len(),
            count(Status::Failed),
            count(Status::Error),
            count(Status::Skipped),
            s.started
                .map(|t| format!(" timestamp=\"{}\"", t.format("%Y-%m-%dT%H:%M:%S")))
                .unwrap_or_default()
        );
        for r in cases {
            let classname = r.file.trim_end_matches(".curl").replace('/', ".");
            let _ = write!(
                out,
                "    <testcase name=\"{}\" classname=\"{}\" file=\"{}\" time=\"{:.3}\"",
                xml_escape(&r.name),
                xml_escape(&classname),
                xml_escape(&r.file),
                r.time_ms / 1000.0
            );
            let failures: Vec<&AssertionResult> =
                r.assertions.iter().filter(|a| !a.passed).collect();
            match r.status {
                Status::Passed => out.push_str("/>\n"),
                Status::Skipped => out.push_str(">\n      <skipped/>\n    </testcase>\n"),
                Status::Error => {
                    let msg = r.error.clone().unwrap_or_default();
                    let _ = write!(
                        out,
                        ">\n      <error message=\"{}\" type=\"error\"/>\n    </testcase>\n",
                        xml_escape(msg.lines().next().unwrap_or_default())
                    );
                }
                Status::Failed => {
                    let first = failures
                        .first()
                        .map(|a| format!("{}: {}", a.name, a.message.clone().unwrap_or_default()))
                        .unwrap_or_default();
                    let body: Vec<String> = failures
                        .iter()
                        .map(|a| format!("{}: {}", a.name, a.message.clone().unwrap_or_default()))
                        .collect();
                    let _ = write!(
                        out,
                        ">\n      <failure message=\"{}\" type=\"assertion\">{}</failure>\n    </testcase>\n",
                        xml_escape(&first),
                        xml_escape(&body.join("\n"))
                    );
                }
            }
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{ErrorKind, Summary};

    fn report() -> RunReport {
        let mut failed = StepResult::new(
            "users/get-user.curl".into(),
            "Get <user>".into(),
            1,
            Status::Failed,
        );
        failed.http_status = Some(404);
        failed.time_ms = 12.0;
        failed.assertions = vec![
            AssertionResult {
                name: "status is 200".into(),
                passed: false,
                message: Some("got 404".into()),
            },
            AssertionResult {
                name: "time ≤ 500 ms".into(),
                passed: true,
                message: None,
            },
        ];
        let mut err = StepResult::new("b.curl".into(), "B".into(), 1, Status::Error);
        err.error_kind = Some(ErrorKind::Transport);
        err.error = Some("Failed to connect & stuff".into());
        RunReport {
            summary: Summary {
                iterations: 1,
                total: 4,
                passed: 1,
                failed: 1,
                errors: 1,
                skipped: 1,
                duration_ms: 50.0,
                ..Default::default()
            },
            results: vec![
                StepResult::new("a.curl".into(), "A".into(), 1, Status::Passed),
                failed,
                err,
                StepResult::new("c.curl".into(), "C".into(), 1, Status::Skipped),
            ],
        }
    }

    #[test]
    fn junit_output() {
        let xml = junit(&report());
        assert!(xml.contains("<testsuites name=\"curly\" tests=\"4\" failures=\"1\" errors=\"1\" skipped=\"1\" time=\"0.050\">"), "{xml}");
        assert!(xml.contains("<testcase name=\"Get &lt;user&gt;\" classname=\"users.get-user\" file=\"users/get-user.curl\" time=\"0.012\">"), "{xml}");
        assert!(xml.contains("<failure message=\"status is 200: got 404\" type=\"assertion\">status is 200: got 404</failure>"));
        assert!(xml.contains("<error message=\"Failed to connect &amp; stuff\" type=\"error\"/>"));
        assert!(xml.contains("<skipped/>"));
        assert!(quick_xml::Reader::from_str(&xml).read_event().is_ok());
    }

    #[test]
    fn json_and_text_output() {
        let r = report();
        let v: serde_json::Value =
            serde_json::from_str(&render(&r, Format::Json).unwrap()).unwrap();
        assert_eq!(v["summary"]["failed"], 1);
        assert_eq!(v["results"][1]["assertions"][0]["message"], "got 404");
        assert_eq!(v["results"][2]["error_kind"], "transport");
        let p = Paint { on: false };
        assert_eq!(
            step_line(&r.results[1], p, false, false),
            "✗ users/get-user.curl  404  12.0 ms\n    ✗ status is 200: got 404\n"
        );
        assert!(summary_line(&r, p).starts_with(
            "4 requests: 1 passed, 1 failed, 1 errors, 1 skipped (2 checks) in 0.05 s"
        ));
        assert!(parse_spec("xml=a").is_err());
        assert_eq!(
            parse_spec("junit=out/r.xml").unwrap(),
            (Format::Junit, PathBuf::from("out/r.xml"))
        );
    }
}
