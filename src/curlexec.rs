//! Runs the system curl binary and captures exactly what it sent and received.
//!
//! curly appends capture options *after* the request file, where curl's
//! last-option-wins rule makes them take effect:
//! `-sS --no-include -o <body> -D <headers> --trace <trace> -w %{json}`.
//! Everything else (TLS, redirects, proxies, cookies) is curl's own behavior.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::secrets::write_private;
use crate::vars::ConfigLayer;

/// Oldest curl with `--variable` and `--expand-*`.
pub const MIN_CURL: (u32, u32, u32) = (8, 3, 0);

/// The detected curl binary.
#[derive(Debug, Clone)]
pub struct Curl {
    /// Path or name used to run it.
    pub path: String,
    /// Version triple.
    pub version: (u32, u32, u32),
    /// Supported protocols (`http`, `https`, `ws`, ...).
    pub protocols: Vec<String>,
}

/// Parses `curl --version` output into version and protocols.
pub fn parse_version(out: &str) -> Result<((u32, u32, u32), Vec<String>)> {
    let first = out.lines().next().unwrap_or_default();
    let ver = first
        .split_whitespace()
        .nth(1)
        .context("unexpected `curl --version` output")?;
    let mut parts = ver
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let version = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    let protocols = out
        .lines()
        .find_map(|l| l.strip_prefix("Protocols:"))
        .map(|p| p.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    Ok((version, protocols))
}

impl Curl {
    /// Runs `curl --version` and checks the minimum version.
    pub fn detect(path: &str) -> Result<Curl> {
        let out = Command::new(path)
            .arg("--version")
            .output()
            .with_context(|| format!("cannot run `{path}`; is curl installed?"))?;
        let (version, protocols) = parse_version(&String::from_utf8_lossy(&out.stdout))?;
        if version < MIN_CURL {
            bail!(
                "curl {}.{}.{} is too old; curly needs 8.3.0 or newer for --variable",
                version.0,
                version.1,
                version.2
            );
        }
        Ok(Curl {
            path: path.into(),
            version,
            protocols,
        })
    }

    /// Version as `8.7.1`.
    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.version.0, self.version.1, self.version.2)
    }
}

/// What curl sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RequestRecord {
    /// HTTP method.
    pub method: String,
    /// Effective URL.
    pub url: String,
    /// Request headers in order.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    #[serde(skip)]
    pub body: Vec<u8>,
}

/// What the server returned.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ResponseRecord {
    /// Status code.
    pub status: u16,
    /// Protocol from the status line, e.g. `HTTP/1.1` or `HTTP/2`.
    pub http_version: String,
    /// Reason phrase (empty for HTTP/2+).
    pub reason: String,
    /// Response headers in order.
    pub headers: Vec<(String, String)>,
    /// Body size as received, before redaction or truncation.
    pub size: usize,
    /// Response body bytes.
    #[serde(skip)]
    pub body: Vec<u8>,
}

impl ResponseRecord {
    /// First header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `Content-Type` header, if any.
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }
}

/// Timing breakdown in milliseconds, from curl's `-w %{json}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Timing {
    /// DNS lookup finished.
    pub dns_ms: f64,
    /// TCP connect finished.
    pub connect_ms: f64,
    /// TLS handshake finished (0 for plain HTTP).
    pub tls_ms: f64,
    /// First response byte.
    pub ttfb_ms: f64,
    /// Whole transfer.
    pub total_ms: f64,
}

/// One request/response pair as executed by curl.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Exchange {
    /// Request as sent.
    pub request: RequestRecord,
    /// Response, if one was received.
    pub response: Option<ResponseRecord>,
    /// Timings.
    pub timing: Timing,
    /// curl's exit code.
    pub curl_exit: i32,
    /// curl's error message, if it failed.
    pub error: Option<String>,
}

/// A fully specified curl run.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// Collection root; curl runs with this as its working directory.
    pub root: PathBuf,
    /// `-K` chain before the request file, lowest precedence first.
    pub layers: Vec<ConfigLayer>,
    /// The request: a collection-relative file, or generated config (token requests).
    pub request: ConfigLayer,
    /// Extra environment for the child process (secret values).
    pub child_env: Vec<(String, String)>,
}

impl Invocation {
    /// Builds the argument list; `layer_paths` are the files for each layer and the request.
    fn args(&self, layer_paths: &[PathBuf], capture: &Path) -> Vec<String> {
        let mut args = Vec::new();
        for f in layer_paths {
            args.push("-K".into());
            args.push(f.display().to_string());
        }
        args.extend(
            [
                "-sS",
                "--no-include",
                "-o",
                &capture.join("body").display().to_string(),
                "-D",
                &capture.join("headers").display().to_string(),
                "--trace",
                &capture.join("trace").display().to_string(),
                "-w",
                "%{json}",
            ]
            .map(String::from),
        );
        args
    }

    /// Runs curl and parses its output.
    pub fn execute(&self, curl: &Curl) -> Result<Exchange> {
        let tmp = tempfile::Builder::new().prefix("curly-").tempdir()?;
        let mut layer_paths = Vec::new();
        for (i, layer) in self
            .layers
            .iter()
            .chain(std::iter::once(&self.request))
            .enumerate()
        {
            match layer {
                ConfigLayer::File(p) => layer_paths.push(p.clone()),
                ConfigLayer::Text(text) => {
                    let p = tmp.path().join(format!("layer{i}.curl"));
                    write_private(&p, text.as_bytes())?;
                    layer_paths.push(p);
                }
            }
        }
        for name in ["body", "headers", "trace"] {
            write_private(&tmp.path().join(name), b"")?;
        }
        let output = Command::new(&curl.path)
            .args(self.args(&layer_paths, tmp.path()))
            .current_dir(&self.root)
            .envs(self.child_env.iter().map(|(k, v)| (k, v)))
            .output()
            .with_context(|| format!("running {}", curl.path))?;
        let read = |n: &str| std::fs::read(tmp.path().join(n)).unwrap_or_default();
        let write_out: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
        let mut ex = build_exchange(&write_out, &read("trace"), &read("headers"), read("body"));
        ex.curl_exit = output.status.code().unwrap_or(-1);
        if ex.curl_exit != 0 && ex.error.is_none() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            ex.error = Some(if stderr.is_empty() {
                format!("curl exited with code {}", ex.curl_exit)
            } else {
                stderr
            });
        }
        Ok(ex)
    }
}

/// Assembles an [`Exchange`] from curl's outputs.
pub fn build_exchange(
    write_out: &serde_json::Value,
    trace: &[u8],
    headers: &[u8],
    body: Vec<u8>,
) -> Exchange {
    let ms = |k: &str| write_out.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0) * 1000.0;
    let s = |k: &str| {
        write_out
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let (mut request, request_body) = parse_trace(trace);
    request.body = request_body;
    if let Some(m) = s("method") {
        request.method = m;
    }
    if let Some(u) = s("url_effective").or_else(|| s("url")) {
        request.url = u;
    }
    let response = parse_response_headers(headers).map(|mut r| {
        r.size = body.len();
        r.body = body;
        r
    });
    Exchange {
        request,
        response,
        timing: Timing {
            dns_ms: ms("time_namelookup"),
            connect_ms: ms("time_connect"),
            tls_ms: ms("time_appconnect"),
            ttfb_ms: ms("time_starttransfer"),
            total_ms: ms("time_total"),
        },
        curl_exit: write_out
            .get("exitcode")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32,
        error: s("errormsg").filter(|e| !e.is_empty()),
    }
}

/// Matches trace section headers like `=> Send header, 78 bytes (0x4e)`.
static TRACE_SECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(=>|<=) (Send|Recv) (header|data|SSL data), (\d+) bytes").expect("regex")
});

/// Extracts the last request's headers and body from `curl --trace` (hex) output.
pub fn parse_trace(trace: &[u8]) -> (RequestRecord, Vec<u8>) {
    let text = String::from_utf8_lossy(trace);
    let mut requests: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut current: Option<(&'static str, usize)> = None;
    let mut in_request = false;
    for line in text.lines() {
        if let Some(c) = TRACE_SECTION.captures(line) {
            let kind = match (&c[2], &c[3]) {
                ("Send", "header") => "sh",
                ("Send", "data") => "sd",
                ("Recv", _) => "r",
                _ => "",
            };
            let len: usize = c[4].parse().unwrap_or(0);
            if kind == "sh" && !in_request {
                requests.push((Vec::new(), Vec::new()));
                in_request = true;
            }
            if kind == "r" {
                in_request = false;
            }
            current = Some((kind, len));
            continue;
        }
        let Some((kind, remaining)) = current.as_mut() else {
            continue;
        };
        let Some((_, hex)) = line.split_once(": ") else {
            current = None;
            continue;
        };
        let take = (*remaining).min(16);
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .take(take)
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        *remaining -= bytes.len();
        if let Some(req) = requests.last_mut() {
            match *kind {
                "sh" => req.0.extend_from_slice(&bytes),
                "sd" => req.1.extend_from_slice(&bytes),
                _ => {}
            }
        }
    }
    let (head, body) = requests.pop().unwrap_or_default();
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let mut rec = RequestRecord::default();
    if let Some(start) = lines.next() {
        let mut parts = start.split_whitespace();
        rec.method = parts.next().unwrap_or_default().into();
        rec.url = parts.next().unwrap_or_default().into();
    }
    rec.headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    (rec, body)
}

/// Parses the final response block from a `-D` header dump (skipping 1xx and redirects).
pub fn parse_response_headers(dump: &[u8]) -> Option<ResponseRecord> {
    let text = String::from_utf8_lossy(dump).replace("\r\n", "\n");
    let block = text
        .split("\n\n")
        .filter(|b| b.starts_with("HTTP/"))
        .last()?;
    let mut lines = block.lines();
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let http_version = parts.next()?.to_string();
    let status = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or_default().trim().to_string();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    Some(ResponseRecord {
        status,
        http_version,
        reason,
        headers,
        size: 0,
        body: Vec::new(),
    })
}

/// Renders an argv as a copy-pasteable shell command.
pub fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%,".contains(c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_output() {
        let (v, p) = parse_version("curl 8.7.1 (x86_64-apple-darwin) libcurl/8.7.1\nRelease-Date: x\nProtocols: http https ws\nFeatures: IPv6\n").unwrap();
        assert_eq!(v, (8, 7, 1));
        assert_eq!(p, vec!["http", "https", "ws"]);
        assert!((8, 2, 9) < MIN_CURL);
    }

    fn hex_section(dir: &str, kind: &str, data: &[u8]) -> String {
        let mut s = format!("{dir} {kind}, {} bytes (0x{:x})\n", data.len(), data.len());
        for (i, chunk) in data.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = chunk
                .iter()
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect();
            s.push_str(&format!("{:04x}: {:<48} {ascii}\n", i * 16, hex.join(" ")));
        }
        s
    }

    #[test]
    fn parses_trace_last_request_exactly() {
        let mut t = String::from("== Info: connected\n");
        t += &hex_section("=>", "Send header", b"GET /old HTTP/1.1\r\nHost: a\r\n\r\n");
        t += &hex_section("<=", "Recv header", b"HTTP/1.1 302 Found\r\n");
        t += &hex_section(
            "=>",
            "Send header",
            b"POST /new HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer abc\r\n\r\n",
        );
        let body = b"{\"a\":1}\nline two with 61 62 hex-looking text\n";
        t += &hex_section("=>", "Send data", body);
        t += &hex_section("<=", "Recv header", b"HTTP/1.1 200 OK\r\n");
        let (req, b) = parse_trace(t.as_bytes());
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "/new");
        assert_eq!(
            req.headers,
            vec![
                ("Host".into(), "a".into()),
                ("Authorization".into(), "Bearer abc".into())
            ]
        );
        assert_eq!(b, body);
    }

    #[test]
    fn parses_final_response_block() {
        let dump = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\nHTTP/2 200 \r\ncontent-type: application/json\r\nx-a: b: c\r\n\r\n";
        let r = parse_response_headers(dump).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.http_version, "HTTP/2");
        assert_eq!(r.content_type(), Some("application/json"));
        assert_eq!(r.header("X-A"), Some("b: c"));
        assert!(parse_response_headers(b"").is_none());
    }

    #[test]
    fn shell_join_quotes() {
        assert_eq!(
            shell_join(&["curl".into(), "-K".into(), "a b.curl".into(), "it's".into()]),
            "curl -K 'a b.curl' 'it'\\''s'"
        );
    }
}
