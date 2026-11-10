//! Collection runner: ordered runs over files and folders, data-driven
//! iterations, captures passed between requests, and per-step results.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::assertions::{AssertionResult, EvalInput, TestFile, evaluate};
use crate::curlexec::{Curl, Exchange};
use crate::folder;
use crate::project::Project;
use crate::request::RunOptions;

/// Runner options.
#[derive(Debug, Clone, Default)]
pub struct RunnerOptions {
    /// Environment name.
    pub env: Option<String>,
    /// `--var` overrides.
    pub vars: Vec<(String, String)>,
    /// Stop at the first failure or error.
    pub bail: bool,
    /// Record requests in history.
    pub record: bool,
    /// Keep unredacted exchanges for terminal display.
    pub show_secrets: bool,
}

/// Outcome of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Response received and every check held.
    Passed,
    /// A check failed.
    Failed,
    /// The request could not run (bad file, undefined variable, transport error).
    Error,
    /// Not run because an earlier step failed with `--bail`.
    Skipped,
}

/// Why a step errored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorKind {
    /// Invalid request file, sidecar, or variables.
    Config,
    /// curl could not complete the transfer.
    Transport,
}

/// Result of one request in a run.
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    /// Collection-relative request file.
    pub file: String,
    /// Display name (`@name` or file stem).
    pub name: String,
    /// 1-based iteration number.
    pub iteration: usize,
    /// Outcome.
    pub status: Status,
    /// Error kind when `status` is `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<ErrorKind>,
    /// HTTP status, if a response arrived.
    pub http_status: Option<u16>,
    /// Total time in milliseconds.
    pub time_ms: f64,
    /// Check results (secrets redacted).
    pub assertions: Vec<AssertionResult>,
    /// Names of variables captured by this step.
    pub captured: Vec<String>,
    /// Error message (secrets redacted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// History entry id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_id: Option<i64>,
    /// Exchange for display (redacted unless `show_secrets`).
    #[serde(skip)]
    pub exchange: Option<Exchange>,
}

impl StepResult {
    /// A result with no response data yet.
    pub fn new(file: String, name: String, iteration: usize, status: Status) -> StepResult {
        StepResult {
            file,
            name,
            iteration,
            status,
            error_kind: None,
            http_status: None,
            time_ms: 0.0,
            assertions: vec![],
            captured: vec![],
            error: None,
            history_id: None,
            exchange: None,
        }
    }
}

/// Totals for a run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// When the run started.
    pub started: Option<DateTime<Utc>>,
    /// Environment used.
    pub env: Option<String>,
    /// Number of iterations (data rows, or 1).
    pub iterations: usize,
    /// Steps planned (requests × iterations).
    pub total: usize,
    /// Passed steps.
    pub passed: usize,
    /// Failed steps.
    pub failed: usize,
    /// Errored steps.
    pub errors: usize,
    /// Skipped steps.
    pub skipped: usize,
    /// Wall-clock duration.
    pub duration_ms: f64,
}

/// A finished run.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    /// Totals.
    pub summary: Summary,
    /// Every step in order.
    pub results: Vec<StepResult>,
}

impl RunReport {
    /// Process exit code: 2 for config errors, 3 for transport errors, 1 for failed checks, else 0.
    pub fn exit_code(&self) -> i32 {
        let kinds: Vec<_> = self.results.iter().filter_map(|r| r.error_kind).collect();
        if kinds.contains(&ErrorKind::Config) {
            2
        } else if kinds.contains(&ErrorKind::Transport) {
            3
        } else if self.summary.failed > 0 {
            1
        } else {
            0
        }
    }
}

/// Expands collection-relative targets (files or folders) into ordered request files.
pub fn plan(project: &Project, targets: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for t in targets {
        if project.root.join(t).is_dir() {
            out.extend(folder::expand(project, t)?);
        } else {
            out.push(t.clone());
        }
    }
    if out.is_empty() {
        bail!("no request files to run");
    }
    Ok(out)
}

/// The `data` file of a single folder target, resolved against the root.
pub fn folder_data(project: &Project, targets: &[PathBuf]) -> Result<Option<PathBuf>> {
    let [only] = targets else { return Ok(None) };
    if !project.root.join(only).is_dir() {
        return Ok(None);
    }
    Ok(folder::load(&project.root.join(only))?
        .and_then(|c| c.data)
        .map(|d| project.root.join(d)))
}

/// Loads data rows from CSV (header row required) or JSON (array of objects).
pub fn load_data(path: &Path) -> Result<Vec<Vec<(String, String)>>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading data file {}", path.display()))?;
    let is_json = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
    let rows = if is_json {
        let v: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let arr = v
            .as_array()
            .with_context(|| format!("{} must contain a JSON array of objects", path.display()))?;
        arr.iter()
            .enumerate()
            .map(|(i, row)| {
                let obj = row.as_object().with_context(|| {
                    format!("{}: row {} is not an object", path.display(), i + 1)
                })?;
                Ok(obj
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| v.to_string()),
                        )
                    })
                    .collect())
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let mut reader = csv::ReaderBuilder::new()
            .trim(csv::Trim::Headers)
            .from_reader(text.as_bytes());
        let headers = reader.headers()?.clone();
        reader
            .records()
            .map(|r| {
                Ok(headers
                    .iter()
                    .zip(r?.iter())
                    .map(|(h, v)| (h.to_string(), v.to_string()))
                    .collect())
            })
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("parsing {}", path.display()))?
    };
    if rows.is_empty() {
        bail!("data file {} has no rows", path.display());
    }
    Ok(rows)
}

fn title_of(project: &Project, rel: &Path) -> String {
    crate::curlconf::RequestSpec::load(&project.root, rel)
        .map(|s| s.title())
        .unwrap_or_else(|_| rel.display().to_string())
}

/// Runs one step and returns its result plus new captures.
fn run_step(
    project: &Project,
    curl: &Curl,
    rel: &Path,
    iteration: usize,
    row: &[(String, String)],
    captured: &[(String, String, bool)],
    opts: &RunnerOptions,
) -> (StepResult, Vec<(String, String, bool)>) {
    let mut result = StepResult::new(
        rel.display().to_string(),
        title_of(project, rel),
        iteration,
        Status::Error,
    );
    let test = match TestFile::load_for(&project.root, rel) {
        Ok(t) => t,
        Err(e) => {
            result.error_kind = Some(ErrorKind::Config);
            result.error = Some(format!("{e:#}"));
            return (result, vec![]);
        }
    };
    let run_opts = RunOptions {
        env: opts.env.clone(),
        vars: opts.vars.clone(),
        captured: captured.to_vec(),
        data: row.to_vec(),
        record: opts.record,
        show_secrets: opts.show_secrets,
        body_override: None,
    };
    let run = match crate::request::run_any(project, curl, rel, &run_opts) {
        Ok(r) => r,
        Err(e) => {
            result.error_kind = Some(ErrorKind::Config);
            result.error = Some(format!("{e:#}"));
            return (result, vec![]);
        }
    };
    result.history_id = run.history_id;
    result.time_ms = run.raw.timing.total_ms;
    result.exchange = Some(run.exchange.clone());
    let Some(resp) = &run.raw.response else {
        result.error_kind = Some(ErrorKind::Transport);
        result.error = Some(
            run.redactor
                .scrub(run.raw.error.as_deref().unwrap_or("no response")),
        );
        return (result, vec![]);
    };
    result.http_status = Some(resp.status);
    let mut new_captures = Vec::new();
    let outcome = match (run.outcome.clone(), test) {
        (Some(done), _) => Some(done),
        (None, Some(test)) => {
            let shown = run.redactor.exchange(&run.raw);
            let input = EvalInput {
                raw: &run.raw,
                shown: &shown,
                vars: &run.vars,
                root: &project.root,
                file: rel,
                env: run.env.as_deref(),
            };
            Some(evaluate(&test, &input))
        }
        (None, None) => None,
    };
    if let Some(outcome) = outcome {
        result.assertions = outcome
            .assertions
            .into_iter()
            .map(|a| AssertionResult {
                name: run.redactor.scrub(&a.name),
                passed: a.passed,
                message: a.message.map(|m| run.redactor.scrub(&m)),
            })
            .collect();
        result.captured = outcome.captures.iter().map(|c| c.name.clone()).collect();
        new_captures = outcome
            .captures
            .into_iter()
            .map(|c| (c.name, c.value, c.secret))
            .collect();
    }
    result.status = if result.assertions.iter().all(|a| a.passed) {
        Status::Passed
    } else {
        Status::Failed
    };
    (result, new_captures)
}

/// Runs `steps` once per data row (once if `rows` is empty), calling
/// `on_step` after each step.
pub fn run(
    project: &Project,
    curl: &Curl,
    steps: &[PathBuf],
    rows: &[Vec<(String, String)>],
    opts: &RunnerOptions,
    on_step: &mut dyn FnMut(&StepResult),
) -> RunReport {
    let started = Utc::now();
    let clock = Instant::now();
    let no_data = [Vec::new()];
    let rows: &[Vec<(String, String)>] = if rows.is_empty() { &no_data } else { rows };
    let mut results = Vec::new();
    let mut stopped = false;
    for (i, row) in rows.iter().enumerate() {
        let mut captured: Vec<(String, String, bool)> = Vec::new();
        for rel in steps {
            if stopped {
                results.push(StepResult::new(
                    rel.display().to_string(),
                    title_of(project, rel),
                    i + 1,
                    Status::Skipped,
                ));
                continue;
            }
            let (result, new) = run_step(project, curl, rel, i + 1, row, &captured, opts);
            for c in new {
                captured.retain(|(k, _, _)| *k != c.0);
                captured.push(c);
            }
            on_step(&result);
            if opts.bail && matches!(result.status, Status::Failed | Status::Error) {
                stopped = true;
            }
            results.push(result);
        }
    }
    let count = |s: Status| results.iter().filter(|r| r.status == s).count();
    let summary = Summary {
        started: Some(started),
        env: opts
            .env
            .clone()
            .or(project.config.project.default_env.clone()),
        iterations: rows.len(),
        total: results.len(),
        passed: count(Status::Passed),
        failed: count(Status::Failed),
        errors: count(Status::Error),
        skipped: count(Status::Skipped),
        duration_ms: clock.elapsed().as_secs_f64() * 1000.0,
    };
    RunReport { summary, results }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_csv_and_json_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let csv = tmp.path().join("d.csv");
        std::fs::write(&csv, "user_id, name\n1,\"Ada, Countess\"\n2,Alan\n").unwrap();
        let rows = load_data(&csv).unwrap();
        assert_eq!(
            rows[0],
            vec![
                ("user_id".into(), "1".into()),
                ("name".into(), "Ada, Countess".into())
            ]
        );
        assert_eq!(rows.len(), 2);
        let json = tmp.path().join("d.json");
        std::fs::write(&json, r#"[{"id": 1, "ok": true, "name": "x"}]"#).unwrap();
        assert_eq!(
            load_data(&json).unwrap()[0],
            vec![
                ("id".into(), "1".into()),
                ("ok".into(), "true".into()),
                ("name".into(), "x".into())
            ]
        );
        std::fs::write(&json, "[]").unwrap();
        assert!(load_data(&json).is_err());
        std::fs::write(&json, "[1]").unwrap();
        assert!(load_data(&json).is_err());
    }

    #[test]
    fn exit_codes_prioritize_errors() {
        let step = |status, kind| StepResult {
            error_kind: kind,
            ..StepResult::new(String::new(), String::new(), 1, status)
        };
        let report = |results: Vec<StepResult>| {
            let failed = results
                .iter()
                .filter(|r| r.status == Status::Failed)
                .count();
            RunReport {
                summary: Summary {
                    failed,
                    ..Default::default()
                },
                results,
            }
        };
        assert_eq!(report(vec![step(Status::Passed, None)]).exit_code(), 0);
        assert_eq!(report(vec![step(Status::Failed, None)]).exit_code(), 1);
        assert_eq!(
            report(vec![
                step(Status::Failed, None),
                step(Status::Error, Some(ErrorKind::Transport))
            ])
            .exit_code(),
            3
        );
        assert_eq!(
            report(vec![
                step(Status::Error, Some(ErrorKind::Transport)),
                step(Status::Error, Some(ErrorKind::Config))
            ])
            .exit_code(),
            2
        );
    }
}
