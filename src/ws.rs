//! WebSocket requests (`.ws` files).
//!
//! A `.ws` file uses curl config syntax with the options that make sense for
//! a WebSocket handshake: `url`, `header`, `user-agent`, `connect-timeout`,
//! `cacert`, `tlsv1.2`, and request-local `variable` lines (plus their
//! `expand-` forms). Messages are scripted with `[[step]]` entries in the
//! test sidecar, or typed interactively with `curly ws -i`.
//!
//! The system curl cannot script WebSocket messages, so curly speaks the
//! protocol itself (tungstenite). TLS uses rustls with the OS trust store and
//! requires TLS 1.3 unless the file opts into `tlsv1.2`.

use std::collections::BTreeMap;
use std::io::{BufRead, Write as _};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::{HeaderName, HeaderValue};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, Message, WebSocket};

use crate::assertions::{AssertionResult, Outcome, Step, TestFile, evaluate_message};
use crate::curlconf::{RequestSpec, substitute};
use crate::curlexec::{Curl, Exchange, RequestRecord, ResponseRecord, Timing};
use crate::project::Project;
use crate::redact::Redactor;
use crate::request::{RunOptions, RunResult, finish, prepare};
use crate::vars::{Source, parse_variable_arg};

/// Options a `.ws` file may use (by base name, so `expand-` forms count too).
pub const SUPPORTED_OPTIONS: &[&str] = &[
    "url",
    "header",
    "user-agent",
    "connect-timeout",
    "cacert",
    "tlsv1.2",
    "tlsv1.3",
    "variable",
];

/// How long a script waits for messages when it has no steps.
const IDLE_LISTEN: Duration = Duration::from_millis(500);

/// A resolved WebSocket target.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// `ws://` or `wss://` URL.
    pub url: String,
    /// Handshake headers.
    pub headers: Vec<(String, String)>,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Allow TLS 1.2 (otherwise TLS 1.3 only).
    pub tls12: bool,
    /// Extra CA bundle (PEM), collection-relative.
    pub cacert: Option<PathBuf>,
}

/// Problems with options in a `.ws` file (for lint).
pub fn unsupported_options(spec: &RequestSpec) -> Vec<(usize, String)> {
    spec.config
        .entries
        .iter()
        .filter(|e| !SUPPORTED_OPTIONS.contains(&e.base_name()))
        .map(|e| {
            (
                e.line,
                format!(
                    "`{}` is not supported in .ws files (supported: {})",
                    e.option,
                    SUPPORTED_OPTIONS.join(", ")
                ),
            )
        })
        .collect()
}

/// Builds the target from a parsed `.ws` file and variable values.
pub fn target(
    project: &Project,
    spec: &RequestSpec,
    vars: &BTreeMap<String, String>,
) -> Result<Target> {
    if let Some((line, msg)) = unsupported_options(spec).into_iter().next() {
        bail!("{}:{line}: {msg}", spec.path.display());
    }
    let mut vars = vars.clone();
    for (_, arg) in &spec.variables {
        let (name, source) = parse_variable_arg(arg)?;
        let value = match source {
            Source::Literal { value } => value,
            Source::File { path } => std::fs::read_to_string(project.root.join(&path))
                .with_context(|| format!("reading {path}"))?,
            Source::Env { default } => std::env::var(&name)
                .ok()
                .or_else(|| match default.map(|d| *d) {
                    Some(Source::Literal { value }) => Some(value),
                    _ => None,
                })
                .unwrap_or_default(),
            Source::Expanded { source } => match *source {
                Source::Literal { value } => substitute(&value, &vars).unwrap_or_default(),
                _ => String::new(),
            },
        };
        vars.insert(name, value);
    }
    let mut t = Target {
        url: String::new(),
        headers: vec![],
        connect_timeout: Duration::from_secs(10),
        tls12: false,
        cacert: None,
    };
    for e in &spec.config.entries {
        let raw = e.value.clone().unwrap_or_default();
        let value = if e.is_expanded() {
            substitute(&raw, &vars)
                .map_err(|m| anyhow::anyhow!("{}:{}: {m}", spec.path.display(), e.line))?
        } else {
            raw
        };
        match e.base_name() {
            "url" => t.url = value,
            "header" => {
                let (k, v) = value.split_once(':').with_context(|| {
                    format!(
                        "{}:{}: header needs `Name: value`",
                        spec.path.display(),
                        e.line
                    )
                })?;
                t.headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            "user-agent" => t.headers.push(("User-Agent".into(), value)),
            "connect-timeout" => {
                t.connect_timeout = Duration::from_secs_f64(
                    value.parse().context("connect-timeout must be seconds")?,
                )
            }
            "cacert" => t.cacert = Some(PathBuf::from(value)),
            "tlsv1.2" => t.tls12 = true,
            _ => {}
        }
    }
    if !(t.url.starts_with("ws://") || t.url.starts_with("wss://")) {
        bail!(
            "{}: url must start with ws:// or wss:// (got `{}`)",
            spec.path.display(),
            t.url
        );
    }
    Ok(t)
}

/// TLS configuration: OS roots (plus `cacert`), TLS 1.3 unless `tls12`.
fn tls_config(project: &Project, t: &Target) -> Result<Arc<rustls::ClientConfig>> {
    crate::tls::client_config(&project.root, t.tls12, t.cacert.as_deref(), &[])
}

/// Direction of a transcript entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Sent by curly.
    Sent,
    /// Received from the server.
    Received,
}

/// One message in a session.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Direction.
    pub dir: Dir,
    /// Milliseconds since the handshake.
    pub at_ms: f64,
    /// Payload.
    pub data: Vec<u8>,
    /// Whether it was a binary message.
    pub binary: bool,
}

/// An open session with its transcript.
pub struct Session {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    started: Instant,
    /// Messages so far.
    pub transcript: Vec<Frame>,
    /// Handshake request as sent.
    pub request: RequestRecord,
    /// Handshake response.
    pub response: ResponseRecord,
    /// Time to complete the handshake.
    pub handshake_ms: f64,
    /// Close code and reason from the server, if it closed.
    pub closed_by_server: Option<String>,
}

/// Opens a WebSocket connection.
pub fn connect(project: &Project, t: &Target) -> Result<Session> {
    let started = Instant::now();
    let mut request = t
        .url
        .as_str()
        .into_client_request()
        .with_context(|| format!("invalid WebSocket URL {}", t.url))?;
    for (k, v) in &t.headers {
        request.headers_mut().append(
            HeaderName::from_bytes(k.as_bytes())?,
            HeaderValue::from_str(v)?,
        );
    }
    let uri = request.uri().clone();
    let host = uri
        .host()
        .context("URL has no host")?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let tls = uri.scheme_str() == Some("wss");
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let addr = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("cannot resolve {host}"))?;
    let stream = TcpStream::connect_timeout(&addr, t.connect_timeout)
        .with_context(|| format!("Failed to connect to {host} port {port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let connector = if tls {
        Connector::Rustls(tls_config(project, t)?)
    } else {
        Connector::Plain
    };
    let sent_headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let (socket, response) =
        match tungstenite::client_tls_with_config(request, stream, None, Some(connector)) {
            Ok(ok) => ok,
            Err(tungstenite::HandshakeError::Failure(tungstenite::Error::Http(resp))) => {
                let body = resp
                    .body()
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                bail!(
                    "WebSocket handshake failed: HTTP {} {}",
                    resp.status().as_u16(),
                    body.trim()
                );
            }
            Err(e) => bail!("WebSocket handshake failed: {e}"),
        };
    let handshake_ms = started.elapsed().as_secs_f64() * 1000.0;
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    Ok(Session {
        socket,
        started: Instant::now(),
        transcript: vec![],
        request: RequestRecord {
            method: "GET".into(),
            url: t.url.clone(),
            headers: sent_headers,
            body: vec![],
        },
        response: ResponseRecord {
            status: response.status().as_u16(),
            http_version: "HTTP/1.1".into(),
            reason: "Switching Protocols".into(),
            headers,
            size: 0,
            body: vec![],
        },
        handshake_ms,
        closed_by_server: None,
    })
}

impl Session {
    fn record(&mut self, dir: Dir, data: Vec<u8>, binary: bool) {
        self.transcript.push(Frame {
            dir,
            at_ms: self.started.elapsed().as_secs_f64() * 1000.0,
            data,
            binary,
        });
    }

    fn set_timeout(&mut self, d: Duration) -> Result<()> {
        let d = Some(d.max(Duration::from_millis(1)));
        match self.socket.get_mut() {
            MaybeTlsStream::Plain(s) => s.set_read_timeout(d)?,
            MaybeTlsStream::Rustls(s) => s.sock.set_read_timeout(d)?,
            _ => {}
        }
        Ok(())
    }

    /// Sends a text message.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.socket.send(Message::text(text))?;
        self.record(Dir::Sent, text.as_bytes().to_vec(), false);
        Ok(())
    }

    /// Sends a binary message.
    pub fn send_binary(&mut self, data: Vec<u8>) -> Result<()> {
        self.socket.send(Message::binary(data.clone()))?;
        self.record(Dir::Sent, data, true);
        Ok(())
    }

    /// Waits up to `timeout` for the next data message; `None` on timeout or close.
    pub fn receive(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, bool)>> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.closed_by_server.is_some() {
                return Ok(None);
            }
            self.set_timeout(left)?;
            match self.socket.read() {
                Ok(Message::Text(t)) => {
                    let data = t.as_bytes().to_vec();
                    self.record(Dir::Received, data.clone(), false);
                    return Ok(Some((data, false)));
                }
                Ok(Message::Binary(b)) => {
                    let data = b.to_vec();
                    self.record(Dir::Received, data.clone(), true);
                    return Ok(Some((data, true)));
                }
                Ok(Message::Close(frame)) => {
                    self.closed_by_server = Some(
                        frame
                            .map(|f| format!("{} {}", u16::from(f.code), f.reason))
                            .unwrap_or_else(|| "no close frame".into()),
                    );
                    return Ok(None);
                }
                Ok(_) => continue,
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    self.closed_by_server
                        .get_or_insert_with(|| "connection closed".into());
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Closes the connection politely.
    pub fn close(&mut self) {
        if self.closed_by_server.is_none() {
            let _ = self.socket.close(None);
            let _ = self.set_timeout(Duration::from_millis(500));
            while self.socket.read().is_ok() {}
        }
    }

    /// The session as an exchange: the handshake plus a `>`/`<` transcript as the body.
    pub fn exchange(&self) -> Exchange {
        let mut body = String::new();
        for f in &self.transcript {
            let arrow = if f.dir == Dir::Sent { '>' } else { '<' };
            if f.binary {
                body.push_str(&format!("{arrow} [binary, {} bytes]\n", f.data.len()));
            } else {
                body.push_str(&format!("{arrow} {}\n", String::from_utf8_lossy(&f.data)));
            }
        }
        if let Some(c) = &self.closed_by_server {
            body.push_str(&format!("closed by server: {c}\n"));
        }
        let mut response = self.response.clone();
        response
            .headers
            .push(("Content-Type".into(), "text/x-websocket-transcript".into()));
        response.size = body.len();
        response.body = body.into_bytes();
        let total = self.handshake_ms + self.started.elapsed().as_secs_f64() * 1000.0;
        Exchange {
            request: self.request.clone(),
            response: Some(response),
            timing: Timing {
                ttfb_ms: self.handshake_ms,
                total_ms: total,
                ..Default::default()
            },
            curl_exit: 0,
            error: None,
        }
    }
}

/// Runs a step script; returns check results, captures, and secrets learned.
fn run_steps(
    project: &Project,
    rel: &Path,
    session: &mut Session,
    steps: &[Step],
    vars: &mut BTreeMap<String, String>,
    redactor: &Redactor,
) -> Outcome {
    let mut out = Outcome::default();
    for (i, step) in steps.iter().enumerate() {
        let n = i + 1;
        let result: Result<()> = (|| {
            if let Some(text) = &step.send {
                let text = substitute(text, vars).map_err(|e| anyhow::anyhow!(e))?;
                session.send_text(&text)?;
            } else if let Some(file) = &step.send_file {
                let data = std::fs::read(project.root.join(file))
                    .with_context(|| format!("reading {file}"))?;
                session.send_binary(data)?;
            } else if let Some(ms) = step.receive {
                match session.receive(Duration::from_millis(ms))? {
                    None => {
                        let why = session
                            .closed_by_server
                            .clone()
                            .map(|c| format!("connection closed ({c})"))
                            .unwrap_or_else(|| format!("no message within {ms} ms"));
                        out.assertions.push(AssertionResult {
                            name: format!("step {n}: receive"),
                            passed: false,
                            message: Some(why),
                        });
                    }
                    Some((data, _)) => {
                        let shown = redactor.body(&data, None);
                        let o = evaluate_message(step, &data, &shown, vars, &project.root, rel);
                        out.assertions.push(AssertionResult {
                            name: format!("step {n}: receive"),
                            passed: true,
                            message: None,
                        });
                        out.assertions
                            .extend(o.assertions.into_iter().map(|a| AssertionResult {
                                name: format!("step {n}: {}", a.name),
                                ..a
                            }));
                        for c in o.captures {
                            vars.insert(c.name.clone(), c.value.clone());
                            out.captures.push(c);
                        }
                    }
                }
            } else if let Some(ms) = step.sleep_ms {
                std::thread::sleep(Duration::from_millis(ms));
            } else if step.close {
                session.close();
            }
            Ok(())
        })();
        if let Err(e) = result {
            out.assertions.push(AssertionResult {
                name: format!("step {n}"),
                passed: false,
                message: Some(redactor.scrub(&format!("{e:#}"))),
            });
            break;
        }
    }
    if steps.is_empty() {
        while let Ok(Some(_)) = session.receive(IDLE_LISTEN) {}
    }
    session.close();
    out
}

/// Runs a `.ws` request: connects, plays its `[[step]]` script, and records history.
pub fn run(project: &Project, curl: &Curl, rel: &Path, opts: &RunOptions) -> Result<RunResult> {
    let prepared = prepare(project, curl, rel, opts)?;
    let mut vars = prepared.ctx.values(&project.root);
    let target = target(project, &prepared.spec, &vars)?;
    let steps = TestFile::load_for(&project.root, rel)?
        .map(|t| t.step)
        .unwrap_or_default();
    let redactor = Redactor::new(
        &project.config.redact,
        prepared.ctx.secret_values(&project.root),
    )?;
    let (raw, outcome, extra) = match connect(project, &target) {
        Ok(mut session) => {
            let outcome = run_steps(project, rel, &mut session, &steps, &mut vars, &redactor);
            let extra: Vec<(String, String)> = outcome
                .captures
                .iter()
                .filter(|c| c.secret)
                .map(|c| (c.name.clone(), c.value.clone()))
                .collect();
            (session.exchange(), Some(outcome), extra)
        }
        Err(e) => {
            let ex = Exchange {
                request: RequestRecord {
                    method: "GET".into(),
                    url: target.url.clone(),
                    headers: target.headers.clone(),
                    body: vec![],
                },
                response: None,
                curl_exit: 0,
                error: Some(format!("{e:#}")),
                ..Default::default()
            };
            (ex, None, vec![])
        }
    };
    finish(project, rel, prepared, raw, opts, outcome, extra)
}

/// Interactive session: lines from stdin are sent, messages are printed.
/// `/quit` closes; `/binary FILE` sends a file. Returns the transcript.
pub fn interactive(
    project: &Project,
    curl: &Curl,
    rel: &Path,
    opts: &RunOptions,
    color: bool,
) -> Result<RunResult> {
    let prepared = prepare(project, curl, rel, opts)?;
    let target = target(project, &prepared.spec, &prepared.ctx.values(&project.root))?;
    let redactor = Redactor::new(
        &project.config.redact,
        prepared.ctx.secret_values(&project.root),
    )?;
    let mut session = connect(project, &target)?;
    let p = crate::view::Paint { on: color };
    eprintln!(
        "{}",
        p.dim(&format!(
            "connected to {} (HTTP {}); type messages, /quit to close",
            target.url, session.response.status
        ))
    );
    let (tx, rx) = mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(Some(l)).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(None);
    });
    let mut eof_at: Option<Instant> = None;
    let show = |data: &[u8], binary: bool| -> String {
        if binary {
            return format!("[binary, {} bytes]", data.len());
        }
        let shown = if opts.show_secrets {
            data.to_vec()
        } else {
            redactor.body(data, None)
        };
        let text = String::from_utf8_lossy(&shown).into_owned();
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => crate::view::highlight(
                crate::view::BodyKind::Json,
                &serde_json::to_string(&v).unwrap_or(text),
                color,
            ),
            Err(_) => text,
        }
    };
    loop {
        match rx.try_recv() {
            Ok(Some(line)) if line.trim() == "/quit" || line.trim() == "/close" => break,
            Ok(Some(line)) if line.trim_start().starts_with("/binary ") => {
                let file = line.trim_start()["/binary ".len()..].trim().to_string();
                match std::fs::read(&file) {
                    Ok(data) => session.send_binary(data)?,
                    Err(e) => eprintln!("{}", p.red(&format!("cannot read {file}: {e}"))),
                }
            }
            Ok(Some(line)) if !line.is_empty() => session.send_text(&line)?,
            Ok(None) => eof_at = eof_at.or(Some(Instant::now())),
            _ => {}
        }
        if eof_at.is_some_and(|t| t.elapsed() > Duration::from_secs(1)) {
            break;
        }
        if let Some((data, binary)) = session.receive(Duration::from_millis(100))? {
            let at = session
                .transcript
                .last()
                .map(|f| f.at_ms)
                .unwrap_or_default();
            let mut out = std::io::stdout().lock();
            let _ = writeln!(
                out,
                "{} {}",
                p.dim(&format!("< {:>8.1} ms", at)),
                show(&data, binary)
            );
            let _ = out.flush();
        }
        if let Some(c) = &session.closed_by_server {
            eprintln!("{}", p.yellow(&format!("closed by server: {c}")));
            break;
        }
    }
    session.close();
    let raw = session.exchange();
    finish(project, rel, prepared, raw, opts, None, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (tempfile::TempDir, Project) {
        let tmp = tempfile::tempdir().unwrap();
        crate::project::init(tmp.path(), &Default::default()).unwrap();
        let p = Project::load(tmp.path()).unwrap();
        (tmp, p)
    }

    fn spec(text: &str) -> RequestSpec {
        RequestSpec::from_config("chat.ws".into(), crate::curlconf::parse(text))
    }

    #[test]
    fn builds_targets() {
        let (_t, p) = project();
        let vars = BTreeMap::from([
            ("WS_URL".to_string(), "ws://h:1".to_string()),
            ("TOKEN".to_string(), "t0k".to_string()),
        ]);
        let t = target(&p, &spec("variable = \"room=lobby\"\nexpand-url = \"{{WS_URL}}/chat?room={{room:url}}\"\nexpand-header = \"Authorization: Bearer {{TOKEN}}\"\nuser-agent = \"curly\"\nconnect-timeout = 2.5\ntlsv1.2\n"), &vars).unwrap();
        assert_eq!(t.url, "ws://h:1/chat?room=lobby");
        assert_eq!(
            t.headers,
            vec![
                ("Authorization".into(), "Bearer t0k".into()),
                ("User-Agent".into(), "curly".into())
            ]
        );
        assert_eq!(t.connect_timeout, Duration::from_millis(2500));
        assert!(t.tls12);
        assert!(
            target(&p, &spec("url = \"http://x\"\n"), &vars)
                .unwrap_err()
                .to_string()
                .contains("ws:// or wss://")
        );
        let err = target(&p, &spec("url = \"ws://x\"\ndata = \"x\"\n"), &vars)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("`data` is not supported in .ws files"),
            "{err}"
        );
    }

    #[test]
    fn tls_defaults_to_1_3_only() {
        let (_t, p) = project();
        let base = Target {
            url: "wss://x".into(),
            headers: vec![],
            connect_timeout: Duration::from_secs(1),
            tls12: false,
            cacert: None,
        };
        assert!(tls_config(&p, &base).is_ok());
        assert!(
            tls_config(
                &p,
                &Target {
                    tls12: true,
                    ..base.clone()
                }
            )
            .is_ok()
        );
        let err = tls_config(
            &p,
            &Target {
                cacert: Some("missing.pem".into()),
                ..base
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("reading cacert missing.pem"), "{err}");
    }
}
