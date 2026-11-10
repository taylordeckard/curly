//! Terminal rendering of exchanges: status line, timing, headers, and a
//! pretty-printed, syntax-highlighted body.

use std::sync::LazyLock;

use anyhow::Result;
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::{LinesWithEndings, as_24_bit_terminal_escaped};

use crate::curlexec::Exchange;
use crate::filter::Filter;

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);
static THEME: LazyLock<Theme> = LazyLock::new(|| {
    let mut set = ThemeSet::load_defaults();
    set.themes.remove("base16-ocean.dark").unwrap_or_default()
});

/// Which parts of the exchange to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Status line, headers, and formatted body.
    #[default]
    Full,
    /// Status line and headers only.
    Headers,
    /// Formatted body only.
    Body,
    /// Response body bytes exactly as received.
    Raw,
}

/// Rendering options.
#[derive(Debug, Clone, Default)]
pub struct ViewOptions {
    /// What to print.
    pub mode: Mode,
    /// Use ANSI colors and syntax highlighting.
    pub color: bool,
    /// Also print the request and a timing breakdown.
    pub verbose: bool,
    /// Optional body filter; when set only filter results are printed.
    pub filter: Option<Filter>,
}

/// Detected body format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// JSON (`application/json`, `+json`).
    Json,
    /// XML (`application/xml`, `text/xml`, `+xml`).
    Xml,
    /// HTML.
    Html,
    /// Other UTF-8 text.
    Text,
    /// Non-UTF-8 bytes.
    Binary,
}

/// Detects the body format from the content type, falling back to sniffing.
pub fn body_kind(content_type: Option<&str>, body: &[u8]) -> BodyKind {
    let ct = content_type.unwrap_or_default().to_ascii_lowercase();
    let Ok(text) = std::str::from_utf8(body) else {
        return BodyKind::Binary;
    };
    if ct.contains("json") {
        return BodyKind::Json;
    }
    if ct.contains("html") {
        return BodyKind::Html;
    }
    if ct.contains("xml") {
        return BodyKind::Xml;
    }
    let t = text.trim_start();
    if (t.starts_with('{') || t.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(t).is_ok()
    {
        BodyKind::Json
    } else if t.to_ascii_lowercase().starts_with("<!doctype html") || t.starts_with("<html") {
        BodyKind::Html
    } else if t.starts_with("<?xml") {
        BodyKind::Xml
    } else {
        BodyKind::Text
    }
}

/// Pretty-prints XML/HTML with two-space indentation; `None` if it is not well-formed.
pub fn pretty_xml(text: &str) -> Option<String> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(e) => writer.write_event(e).ok()?,
            Err(_) => return None,
        }
    }
    String::from_utf8(writer.into_inner()).ok()
}

/// Formats a body for display (no color). Falls back to the original text.
pub fn pretty_body(kind: BodyKind, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    match kind {
        BodyKind::Json => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| text.into_owned()),
        BodyKind::Xml | BodyKind::Html => pretty_xml(&text).unwrap_or_else(|| text.into_owned()),
        BodyKind::Text => text.into_owned(),
        BodyKind::Binary => format!("<binary body, {}>", human_size(body.len())),
    }
}

/// Applies syntax highlighting for `kind` when `color` is set.
pub fn highlight(kind: BodyKind, text: &str, color: bool) -> String {
    let ext = match kind {
        BodyKind::Json => "json",
        BodyKind::Xml => "xml",
        BodyKind::Html => "html",
        _ => return text.to_string(),
    };
    let Some(syntax) = SYNTAXES.find_syntax_by_extension(ext).filter(|_| color) else {
        return text.to_string();
    };
    let mut h = HighlightLines::new(syntax, &THEME);
    let mut out = String::new();
    for line in LinesWithEndings::from(text) {
        match h.highlight_line(line, &SYNTAXES) {
            Ok(ranges) => out.push_str(&as_24_bit_terminal_escaped(&ranges, false)),
            Err(_) => out.push_str(line),
        }
    }
    out.push_str("\x1b[0m");
    out
}

/// Formats a byte count (`512 B`, `1.5 KiB`).
pub fn human_size(n: usize) -> String {
    match n {
        n if n < 1024 => format!("{n} B"),
        n if n < 1024 * 1024 => format!("{:.1} KiB", n as f64 / 1024.0),
        n => format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0)),
    }
}

/// ANSI styling helper that is a no-op when color is off.
#[derive(Debug, Clone, Copy)]
pub struct Paint {
    /// Whether to emit escape codes.
    pub on: bool,
}

impl Paint {
    /// Wraps `s` in SGR code `code`.
    pub fn sgr(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    /// Bold.
    pub fn bold(&self, s: &str) -> String {
        self.sgr("1", s)
    }
    /// Dim.
    pub fn dim(&self, s: &str) -> String {
        self.sgr("2", s)
    }
    /// Green.
    pub fn green(&self, s: &str) -> String {
        self.sgr("32", s)
    }
    /// Red.
    pub fn red(&self, s: &str) -> String {
        self.sgr("31", s)
    }
    /// Yellow.
    pub fn yellow(&self, s: &str) -> String {
        self.sgr("33", s)
    }
    /// Cyan.
    pub fn cyan(&self, s: &str) -> String {
        self.sgr("36", s)
    }
    /// Colors a status code by class.
    pub fn status(&self, code: u16, s: &str) -> String {
        match code {
            200..=299 => self.sgr("1;32", s),
            300..=399 => self.sgr("1;36", s),
            400..=499 => self.sgr("1;33", s),
            _ => self.sgr("1;31", s),
        }
    }
}

fn format_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2} s", ms / 1000.0)
    } else {
        format!("{ms:.1} ms")
    }
}

fn push_headers(out: &mut String, p: Paint, prefix: &str, headers: &[(String, String)]) {
    for (k, v) in headers {
        out.push_str(&format!("{prefix}{}: {v}\n", p.cyan(k)));
    }
}

/// Renders an exchange according to `opts`.
pub fn render(ex: &Exchange, opts: &ViewOptions) -> Result<Vec<u8>> {
    let p = Paint { on: opts.color };
    let Some(resp) = &ex.response else {
        let msg = ex.error.clone().unwrap_or_else(|| "no response".into());
        return Ok(format!(
            "{} {}\n",
            p.red(&if ex.curl_exit > 0 {
                format!("curl error (exit {}):", ex.curl_exit)
            } else {
                "error:".to_string()
            }),
            msg
        )
        .into_bytes());
    };
    if let Some(filter) = &opts.filter {
        let mut out = String::new();
        for v in filter.apply(&resp.body)? {
            let s = serde_json::to_string_pretty(&v)?;
            out.push_str(&highlight(BodyKind::Json, &s, opts.color));
            out.push('\n');
        }
        return Ok(out.into_bytes());
    }
    if opts.mode == Mode::Raw {
        return Ok(resp.body.clone());
    }
    let mut out = String::new();
    if opts.verbose && opts.mode != Mode::Body {
        out.push_str(&p.dim(&format!("> {} {}", ex.request.method, ex.request.url)));
        out.push('\n');
        push_headers(&mut out, p, &p.dim("> "), &ex.request.headers);
        if !ex.request.body.is_empty() {
            let ct = ex
                .request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str());
            let kind = body_kind(ct, &ex.request.body);
            out.push_str(&p.dim(">"));
            out.push('\n');
            out.push_str(&highlight(
                kind,
                &pretty_body(kind, &ex.request.body),
                opts.color,
            ));
            out.push('\n');
        }
        out.push('\n');
    }
    if opts.mode != Mode::Body {
        let status = format!("{} {} {}", resp.http_version, resp.status, resp.reason);
        out.push_str(&format!(
            "{}  {}  {}\n",
            if resp.http_version == "gRPC" {
                p.status(if resp.status == 0 { 200 } else { 500 }, status.trim_end())
            } else {
                p.status(resp.status, status.trim_end())
            },
            p.dim(&format_ms(ex.timing.total_ms)),
            p.dim(&human_size(resp.size.max(resp.body.len())))
        ));
        if opts.verbose {
            let t = &ex.timing;
            out.push_str(&p.dim(&format!(
                "dns {} · connect {} · tls {} · first byte {} · total {}\n",
                format_ms(t.dns_ms),
                format_ms(t.connect_ms),
                format_ms(t.tls_ms),
                format_ms(t.ttfb_ms),
                format_ms(t.total_ms)
            )));
        }
        push_headers(&mut out, p, "", &resp.headers);
    }
    if opts.mode != Mode::Headers && !resp.body.is_empty() {
        if opts.mode == Mode::Full {
            out.push('\n');
        }
        let kind = body_kind(resp.content_type(), &resp.body);
        let body = pretty_body(kind, &resp.body);
        out.push_str(&highlight(kind, &body, opts.color));
        if !body.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curlexec::{RequestRecord, ResponseRecord, Timing};

    fn exchange(ct: &str, body: &[u8]) -> Exchange {
        Exchange {
            request: RequestRecord {
                method: "GET".into(),
                url: "http://h/x".into(),
                headers: vec![("Accept".into(), "*/*".into())],
                body: vec![],
            },
            response: Some(ResponseRecord {
                status: 200,
                http_version: "HTTP/1.1".into(),
                reason: "OK".into(),
                headers: vec![("content-type".into(), ct.into())],
                size: body.len(),
                body: body.to_vec(),
            }),
            timing: Timing {
                total_ms: 12.34,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn text(ex: &Exchange, opts: ViewOptions) -> String {
        String::from_utf8(render(ex, &opts).unwrap()).unwrap()
    }

    #[test]
    fn full_plain_output() {
        let out = text(
            &exchange("application/json", br#"{"a":1}"#),
            ViewOptions::default(),
        );
        assert_eq!(
            out,
            "HTTP/1.1 200 OK  12.3 ms  7 B\ncontent-type: application/json\n\n{\n  \"a\": 1\n}\n"
        );
    }

    #[test]
    fn modes() {
        let ex = exchange("application/json", br#"{"a":1}"#);
        assert_eq!(
            text(
                &ex,
                ViewOptions {
                    mode: Mode::Raw,
                    ..Default::default()
                }
            ),
            r#"{"a":1}"#
        );
        assert_eq!(
            text(
                &ex,
                ViewOptions {
                    mode: Mode::Body,
                    ..Default::default()
                }
            ),
            "{\n  \"a\": 1\n}\n"
        );
        assert!(
            !text(
                &ex,
                ViewOptions {
                    mode: Mode::Headers,
                    ..Default::default()
                }
            )
            .contains("\"a\"")
        );
        let f = text(
            &ex,
            ViewOptions {
                filter: Some(Filter::Jq(".a".into())),
                ..Default::default()
            },
        );
        assert_eq!(f, "1\n");
        let v = text(
            &ex,
            ViewOptions {
                verbose: true,
                ..Default::default()
            },
        );
        assert!(v.starts_with("> GET http://h/x\n> Accept: */*\n"));
        assert!(v.contains("first byte"));
    }

    #[test]
    fn color_adds_escapes_plain_does_not() {
        let ex = exchange("application/json", br#"{"a":1}"#);
        assert!(
            text(
                &ex,
                ViewOptions {
                    color: true,
                    ..Default::default()
                }
            )
            .contains("\x1b[")
        );
        assert!(!text(&ex, ViewOptions::default()).contains('\x1b'));
    }

    #[test]
    fn detects_and_formats_xml_html_binary() {
        assert_eq!(
            body_kind(None, b"<?xml version=\"1.0\"?><a/>"),
            BodyKind::Xml
        );
        assert_eq!(body_kind(Some("text/html"), b"<p>"), BodyKind::Html);
        assert_eq!(body_kind(None, b" [1,2]"), BodyKind::Json);
        assert_eq!(body_kind(None, &[0xff, 0xfe]), BodyKind::Binary);
        assert_eq!(
            pretty_xml("<a><b>x</b></a>").unwrap(),
            "<a>\n  <b>x</b>\n</a>"
        );
        assert_eq!(
            pretty_body(BodyKind::Html, b"<p>unclosed<br>"),
            "<p>unclosed<br>"
        );
        assert_eq!(
            pretty_body(BodyKind::Binary, &[0xff; 3]),
            "<binary body, 3 B>"
        );
    }

    #[test]
    fn curl_errors_render() {
        let ex = Exchange {
            curl_exit: 7,
            error: Some("Failed to connect".into()),
            ..Default::default()
        };
        assert_eq!(
            text(&ex, ViewOptions::default()),
            "curl error (exit 7): Failed to connect\n"
        );
    }
}
