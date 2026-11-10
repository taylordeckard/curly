//! Test sidecars (`<request>.test.toml`): declarative checks, captures, and an
//! optional hook script.
//!
//! Checks are evaluated against the unredacted response, but the values shown
//! in failure messages come from the redacted copy, so a failing check on a
//! token never prints the token.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::curlconf::substitute;
use crate::curlexec::Exchange;
use crate::filter;

/// Suffix of test sidecar files.
pub const TEST_SUFFIX: &str = ".test.toml";

/// `foo/bar.curl` -> `foo/bar.test.toml`.
pub fn sidecar_path(request: &Path) -> PathBuf {
    let stem = request
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    request.with_file_name(format!("{stem}{TEST_SUFFIX}"))
}

/// A parsed test sidecar.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TestFile {
    /// Declarative checks.
    pub expect: Expect,
    /// Values to capture into variables for later requests.
    pub capture: BTreeMap<String, CaptureSpec>,
    /// Optional script run after the checks.
    pub hook: Option<Hook>,
    /// Scripted message exchange for `.ws` requests.
    pub step: Vec<Step>,
}

/// One step of a WebSocket script. Exactly one action per step; `body`,
/// `json`, and `capture` apply to the message received by a `receive` step.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Step {
    /// Send a text message (`{{variables}}` are expanded).
    pub send: Option<String>,
    /// Send the bytes of this collection-relative file as a binary message.
    pub send_file: Option<String>,
    /// Wait up to this many milliseconds for the next message.
    pub receive: Option<u64>,
    /// Pause for this many milliseconds.
    pub sleep_ms: Option<u64>,
    /// Close the connection.
    pub close: bool,
    /// Check on the received message as text.
    pub body: Option<Check>,
    /// JSONPath / jq checks on the received message.
    pub json: Vec<JsonCheck>,
    /// Values to capture from the received message.
    pub capture: BTreeMap<String, CaptureSpec>,
}

impl Step {
    /// Checks that the step has exactly one action and checks only on `receive`.
    fn validate(&self, index: usize) -> Result<()> {
        let actions = [
            self.send.is_some(),
            self.send_file.is_some(),
            self.receive.is_some(),
            self.sleep_ms.is_some(),
            self.close,
        ]
        .iter()
        .filter(|a| **a)
        .count();
        if actions != 1 {
            anyhow::bail!(
                "step {}: needs exactly one of send, send_file, receive, sleep_ms, close",
                index + 1
            );
        }
        let has_checks = self.body.is_some() || !self.json.is_empty() || !self.capture.is_empty();
        if has_checks && self.receive.is_none() {
            anyhow::bail!(
                "step {}: body, json, and capture only apply to `receive` steps",
                index + 1
            );
        }
        for (name, spec) in &self.capture {
            Extract::parse(spec.parts().0)
                .map_err(|e| anyhow::anyhow!("step {} capture `{name}`: {e}", index + 1))?;
        }
        Ok(())
    }
}

/// `[expect]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expect {
    /// Allowed status codes: `200`, `"2xx"`, or a list of either.
    pub status: Option<StatusSpec>,
    /// Upper bound on total time.
    pub max_time_ms: Option<f64>,
    /// JSON Schema file (collection-relative) the body must satisfy.
    pub schema: Option<String>,
    /// Header checks by name (case-insensitive).
    pub headers: BTreeMap<String, Check>,
    /// Check on the whole body as text.
    pub body: Option<Check>,
    /// JSONPath / jq checks.
    pub json: Vec<JsonCheck>,
}

/// One allowed status: an exact code or a class like `"2xx"`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum StatusItem {
    /// Exact code.
    Code(u16),
    /// Class (`"4xx"`) or a code written as a string.
    Class(String),
}

impl StatusItem {
    fn matches(&self, code: u16) -> bool {
        match self {
            StatusItem::Code(c) => *c == code,
            StatusItem::Class(s) => match (s.strip_suffix("xx"), crate::grpc::code_from_name(s)) {
                (_, Some(grpc)) => grpc == code,
                (Some(class), None) => class.parse::<u16>().is_ok_and(|c| c == code / 100),
                (None, None) => s.parse::<u16>().is_ok_and(|c| c == code),
            },
        }
    }

    /// Display form (`200`, `"2xx"`).
    pub fn label(&self) -> String {
        match self {
            StatusItem::Code(c) => c.to_string(),
            StatusItem::Class(s) => s.clone(),
        }
    }
}

/// `status = ...`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum StatusSpec {
    /// A single code or class.
    One(StatusItem),
    /// Any of several.
    Any(Vec<StatusItem>),
}

impl StatusSpec {
    /// All allowed statuses.
    pub fn items(&self) -> Vec<StatusItem> {
        match self {
            StatusSpec::One(i) => vec![i.clone()],
            StatusSpec::Any(v) => v.clone(),
        }
    }
}

/// Comparison operators; several may be combined and all must hold.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ops {
    /// Equal (numbers compare numerically).
    pub eq: Option<Value>,
    /// Not equal.
    pub ne: Option<Value>,
    /// Greater than.
    pub gt: Option<f64>,
    /// Greater than or equal.
    pub gte: Option<f64>,
    /// Less than.
    pub lt: Option<f64>,
    /// Less than or equal.
    pub lte: Option<f64>,
    /// Substring, array element, or object key.
    pub contains: Option<Value>,
    /// Regex match against the string form.
    pub matches: Option<String>,
    /// Presence (`true`) or absence (`false`).
    pub exists: Option<bool>,
    /// JSON type: string, number, integer, boolean, array, object, null.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Length of a string, array, or object.
    pub len: Option<usize>,
}

/// A bare scalar, shorthand for `{ eq = value }`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Scalar {
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// String.
    Str(String),
}

/// A check: a scalar (equality) or an operator table.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Check {
    /// Operator table.
    Ops(Box<Ops>),
    /// Equality shorthand.
    Scalar(Scalar),
}

impl Check {
    /// The check as an operator table.
    pub fn ops(&self) -> Ops {
        match self {
            Check::Ops(o) => (**o).clone(),
            Check::Scalar(s) => Ops {
                eq: Some(match s {
                    Scalar::Bool(b) => Value::Bool(*b),
                    Scalar::Int(i) => Value::from(*i),
                    Scalar::Float(f) => Value::from(*f),
                    Scalar::Str(s) => Value::String(s.clone()),
                }),
                ..Default::default()
            },
        }
    }
}

/// What to read from a response.
#[derive(Debug, Clone, PartialEq)]
pub enum Extract {
    /// JSONPath on the body (`$.id`).
    JsonPath(String),
    /// jq program on the body (`jq:.items | length`).
    Jq(String),
    /// First header with this name (`header:ETag`).
    Header(String),
    /// Status code (`status`).
    Status,
    /// Whole body as text (`body`).
    Body,
    /// First capture group (or whole match) of a regex on the body (`regex:...`).
    Regex(String),
}

impl Extract {
    /// Parses capture syntax.
    pub fn parse(s: &str) -> Result<Extract, String> {
        Ok(if s.starts_with('$') {
            Extract::JsonPath(s.into())
        } else if let Some(j) = s.strip_prefix("jq:") {
            Extract::Jq(j.into())
        } else if let Some(h) = s.strip_prefix("header:") {
            Extract::Header(h.trim().into())
        } else if let Some(r) = s.strip_prefix("regex:") {
            Regex::new(r).map_err(|e| format!("invalid regex `{r}`: {e}"))?;
            Extract::Regex(r.into())
        } else if s == "status" {
            Extract::Status
        } else if s == "body" {
            Extract::Body
        } else {
            return Err(format!(
                "unknown capture source `{s}` (use $.path, jq:EXPR, header:NAME, regex:RE, status, or body)"
            ));
        })
    }

    /// Display form (`$.id`, `header ETag`).
    pub fn label(&self) -> String {
        match self {
            Extract::JsonPath(p) => p.clone(),
            Extract::Jq(j) => format!("jq `{j}`"),
            Extract::Header(h) => format!("header {h}"),
            Extract::Status => "status".into(),
            Extract::Body => "body".into(),
            Extract::Regex(r) => format!("regex `{r}`"),
        }
    }
}

/// One `[[expect.json]]` entry: `path` or `jq` plus operators.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(try_from = "toml::Table")]
pub struct JsonCheck {
    /// What to read.
    pub select: Extract,
    /// Operators to apply.
    pub ops: Ops,
}

impl TryFrom<toml::Table> for JsonCheck {
    type Error = String;

    fn try_from(mut t: toml::Table) -> Result<Self, String> {
        let select =
            match (t.remove("path"), t.remove("jq")) {
                (Some(toml::Value::String(p)), None) if p.starts_with('$') => Extract::JsonPath(p),
                (None, Some(toml::Value::String(j))) => Extract::Jq(j),
                _ => return Err(
                    "each [[expect.json]] needs exactly one of `path = \"$...\"` or `jq = \"...\"`"
                        .into(),
                ),
            };
        let ops: Ops = toml::Value::Table(t)
            .try_into()
            .map_err(|e: toml::de::Error| e.message().to_string())?;
        Ok(JsonCheck { select, ops })
    }
}

/// A capture: `name = "$.id"` or `name = { from = "$.token", secret = true }`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CaptureSpec {
    /// Source only.
    From(String),
    /// Source with options.
    Full {
        /// Source.
        from: String,
        /// Treat the value as a secret (also inferred when redaction masks it).
        #[serde(default)]
        secret: bool,
    },
}

impl CaptureSpec {
    /// `(source, secret)`.
    pub fn parts(&self) -> (&str, bool) {
        match self {
            CaptureSpec::From(f) => (f, false),
            CaptureSpec::Full { from, secret } => (from, *secret),
        }
    }
}

/// `[hook]`: a script that receives the exchange as JSON on stdin.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    /// Executable path, relative to the collection root.
    pub script: String,
    /// Extra arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Kill the script after this many seconds (default 30).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

impl TestFile {
    /// Parses and validates sidecar text.
    pub fn parse(text: &str) -> Result<TestFile> {
        let t: TestFile = toml::from_str(text)?;
        for (i, step) in t.step.iter().enumerate() {
            step.validate(i)?;
        }
        for (name, spec) in &t.capture {
            Extract::parse(spec.parts().0).map_err(|e| anyhow::anyhow!("capture `{name}`: {e}"))?;
        }
        if let Some(s) = &t.expect.status {
            for i in s.items() {
                if let StatusItem::Class(c) = &i
                    && !(c.len() == 3 && (c.ends_with("xx") || c.parse::<u16>().is_ok()))
                    && crate::grpc::code_from_name(c).is_none()
                {
                    anyhow::bail!(
                        "invalid status `{c}` (use 200, \"2xx\", or a gRPC code name like \"NOT_FOUND\")"
                    );
                }
            }
        }
        Ok(t)
    }

    /// Loads the sidecar for `request` (collection-relative) if it exists.
    pub fn load_for(root: &Path, request: &Path) -> Result<Option<TestFile>> {
        let path = root.join(sidecar_path(request));
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)?;
        TestFile::parse(&text)
            .map(Some)
            .with_context(|| format!("parsing {}", sidecar_path(request).display()))
    }

    /// Variable names this sidecar captures (including WebSocket steps).
    pub fn capture_names(&self) -> Vec<String> {
        self.capture
            .keys()
            .chain(self.step.iter().flat_map(|s| s.capture.keys()))
            .cloned()
            .collect()
    }
}

/// Result of one check.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AssertionResult {
    /// Human-readable description, e.g. `$.id eq 1`.
    pub name: String,
    /// Whether it held.
    pub passed: bool,
    /// Failure detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl AssertionResult {
    fn ok(name: String) -> Self {
        AssertionResult {
            name,
            passed: true,
            message: None,
        }
    }
    fn fail(name: String, message: String) -> Self {
        AssertionResult {
            name,
            passed: false,
            message: Some(message),
        }
    }
}

/// A captured variable.
#[derive(Debug, Clone, PartialEq)]
pub struct Capture {
    /// Variable name.
    pub name: String,
    /// Raw value.
    pub value: String,
    /// Whether it must be redacted.
    pub secret: bool,
}

/// Inputs for evaluation.
pub struct EvalInput<'a> {
    /// Unredacted exchange (used for logic and captures).
    pub raw: &'a Exchange,
    /// Exchange as displayed (used for values in messages).
    pub shown: &'a Exchange,
    /// Variables for `{{name}}` in expected values.
    pub vars: &'a BTreeMap<String, String>,
    /// Collection root.
    pub root: &'a Path,
    /// Request file (collection-relative).
    pub file: &'a Path,
    /// Environment name.
    pub env: Option<&'a str>,
}

/// Results of evaluating a sidecar.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Check results in order.
    pub assertions: Vec<AssertionResult>,
    /// Captured variables.
    pub captures: Vec<Capture>,
}

/// Reads `what` from an exchange. `Ok(None)` means "no value".
pub fn extract(ex: &Exchange, what: &Extract) -> Result<Option<Value>, String> {
    let Some(r) = &ex.response else {
        return Ok(None);
    };
    let json =
        || serde_json::from_slice::<Value>(&r.body).map_err(|_| "body is not JSON".to_string());
    let many = |v: Vec<Value>| match v.len() {
        0 => None,
        1 => v.into_iter().next(),
        _ => Some(Value::Array(v)),
    };
    Ok(match what {
        Extract::JsonPath(p) => many(filter::jsonpath(p, &json()?).map_err(|e| e.to_string())?),
        Extract::Jq(j) => many(filter::jq(j, &r.body).map_err(|e| e.to_string())?),
        Extract::Header(h) => r.header(h).map(|v| Value::String(v.into())),
        Extract::Status => Some(Value::from(r.status)),
        Extract::Body => Some(Value::String(String::from_utf8_lossy(&r.body).into_owned())),
        Extract::Regex(re) => {
            let re = Regex::new(re).map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&r.body);
            re.captures(&text).map(|c| {
                Value::String(
                    c.get(1)
                        .or_else(|| c.get(0))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                )
            })
        }
    })
}

/// Compact display form of a value, truncated.
fn show(v: Option<&Value>) -> String {
    let s = match v {
        None => return "nothing".into(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
    };
    if s.chars().count() > 200 {
        format!("{}…", s.chars().take(200).collect::<String>())
    } else {
        s
    }
}

/// String form used for regex and header comparisons.
fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Equality with numeric tolerance and string/scalar leniency: headers are
/// strings, and `{{var}}` expectations always produce strings.
fn json_eq(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::String(s), other @ (Value::Number(_) | Value::Bool(_)))
        | (other @ (Value::Number(_) | Value::Bool(_)), Value::String(s)) => {
            s.as_str() == other.to_string().as_str()
        }
        (a, b) => a == b,
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Replaces `{{name}}` in every string inside `v`.
fn expand(v: &Value, vars: &BTreeMap<String, String>) -> Result<Value, String> {
    Ok(match v {
        Value::String(s) => Value::String(substitute(s, vars)?),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| expand(x, vars))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| Ok((k.clone(), expand(x, vars)?)))
                .collect::<Result<_, String>>()?,
        ),
        other => other.clone(),
    })
}

/// Applies `ops` to `actual`; `shown` is the display version of the same value.
fn check_ops(
    subject: &str,
    ops: &Ops,
    actual: Option<&Value>,
    shown: Option<&Value>,
    vars: &BTreeMap<String, String>,
) -> Vec<AssertionResult> {
    let mut out = Vec::new();
    let got = format!("got {}", show(shown));
    let judge = |name: String, ok: bool| {
        if ok {
            AssertionResult::ok(name)
        } else {
            AssertionResult::fail(name, got.clone())
        }
    };
    let is_empty = *ops == Ops::default();
    if let Some(want) = ops.exists.or(is_empty.then_some(true)) {
        out.push(judge(
            format!("{subject} {}", if want { "exists" } else { "is absent" }),
            actual.is_some() == want,
        ));
    }
    let value_ops = [&ops.eq, &ops.ne, &ops.contains]
        .iter()
        .any(|o| o.is_some())
        || [ops.gt, ops.gte, ops.lt, ops.lte]
            .iter()
            .any(|o| o.is_some())
        || ops.matches.is_some()
        || ops.kind.is_some()
        || ops.len.is_some();
    let Some(actual) = actual else {
        if value_ops {
            out.push(AssertionResult::fail(
                subject.to_string(),
                "no value found".into(),
            ));
        }
        return out;
    };
    let resolve = |v: &Value| expand(v, vars);
    for (op, expected, negate) in [("eq", &ops.eq, false), ("ne", &ops.ne, true)] {
        if let Some(e) = expected {
            match resolve(e) {
                Ok(e) => out.push(judge(
                    format!("{subject} {op} {}", show(Some(&e))),
                    json_eq(actual, &e) != negate,
                )),
                Err(msg) => out.push(AssertionResult::fail(format!("{subject} {op}"), msg)),
            }
        }
    }
    for (op, bound) in [
        ("gt", ops.gt),
        ("gte", ops.gte),
        ("lt", ops.lt),
        ("lte", ops.lte),
    ] {
        if let Some(b) = bound {
            let n = actual
                .as_f64()
                .or_else(|| actual.as_str().and_then(|s| s.parse().ok()));
            let ok = n.is_some_and(|n| match op {
                "gt" => n > b,
                "gte" => n >= b,
                "lt" => n < b,
                _ => n <= b,
            });
            out.push(judge(format!("{subject} {op} {b}"), ok));
        }
    }
    if let Some(c) = &ops.contains {
        match resolve(c) {
            Ok(c) => {
                let ok = match (actual, &c) {
                    (Value::String(s), Value::String(n)) => s.contains(n.as_str()),
                    (Value::Array(items), needle) => items.iter().any(|i| json_eq(i, needle)),
                    (Value::Object(m), Value::String(k)) => m.contains_key(k),
                    _ => false,
                };
                out.push(judge(format!("{subject} contains {}", show(Some(&c))), ok));
            }
            Err(msg) => out.push(AssertionResult::fail(format!("{subject} contains"), msg)),
        }
    }
    if let Some(pattern) = &ops.matches {
        match substitute(pattern, vars)
            .map_err(|e| e.to_string())
            .and_then(|p| Regex::new(&p).map_err(|e| e.to_string()))
        {
            Ok(re) => out.push(judge(
                format!("{subject} matches /{pattern}/"),
                re.is_match(&as_text(actual)),
            )),
            Err(msg) => out.push(AssertionResult::fail(format!("{subject} matches"), msg)),
        }
    }
    if let Some(kind) = &ops.kind {
        let t = type_name(actual);
        out.push(judge(
            format!("{subject} is {kind}"),
            t == kind || (kind == "number" && t == "integer"),
        ));
    }
    if let Some(n) = ops.len {
        let len = match actual {
            Value::String(s) => Some(s.chars().count()),
            Value::Array(a) => Some(a.len()),
            Value::Object(m) => Some(m.len()),
            _ => None,
        };
        out.push(judge(format!("{subject} has length {n}"), len == Some(n)));
    }
    out
}

/// Validates `body` against the JSON Schema at `root/schema`.
fn check_schema(root: &Path, schema: &str, body: &[u8]) -> AssertionResult {
    let name = format!("body matches schema {schema}");
    let run = || -> Result<Vec<String>, String> {
        let path = root.join(schema);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("cannot read {schema}: {e}"))?;
        let schema_json: Value =
            serde_json::from_str(&text).map_err(|e| format!("{schema} is not JSON: {e}"))?;
        let abs = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
        let validator = jsonschema::options()
            .with_base_uri(format!("file://{}", abs.display()))
            .build(&schema_json)
            .map_err(|e| format!("invalid schema {schema}: {e}"))?;
        let instance: Value =
            serde_json::from_slice(body).map_err(|_| "body is not JSON".to_string())?;
        Ok(validator
            .iter_errors(&instance)
            .take(3)
            .map(|e| {
                let at = e.instance_path().to_string();
                format!(
                    "{e} at {}",
                    if at.is_empty() {
                        "the root".to_string()
                    } else {
                        format!("`{at}`")
                    }
                )
            })
            .collect())
    };
    match run() {
        Ok(errors) if errors.is_empty() => AssertionResult::ok(name),
        Ok(errors) => AssertionResult::fail(name, errors.join("; ")),
        Err(msg) => AssertionResult::fail(name, msg),
    }
}

/// Builds the JSON given to hook scripts.
fn hook_input(input: &EvalInput<'_>) -> Value {
    let ex = input.raw;
    let resp = ex.response.as_ref();
    serde_json::json!({
        "file": input.file.display().to_string(),
        "env": input.env,
        "vars": input.vars,
        "request": {
            "method": ex.request.method,
            "url": ex.request.url,
            "headers": ex.request.headers,
            "body": String::from_utf8_lossy(&ex.request.body),
        },
        "response": resp.map(|r| serde_json::json!({
            "status": r.status,
            "headers": r.headers,
            "body": String::from_utf8_lossy(&r.body),
            "json": serde_json::from_slice::<Value>(&r.body).ok(),
        })),
        "timing": ex.timing,
    })
}

/// Hook output (all fields optional).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HookOutput {
    assertions: Vec<HookAssertion>,
    captures: BTreeMap<String, Value>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HookAssertion {
    name: String,
    passed: bool,
    #[serde(default)]
    message: Option<String>,
}

/// Runs a hook script; returns its assertions and captures.
fn run_hook(hook: &Hook, input: &EvalInput<'_>) -> (Vec<AssertionResult>, Vec<Capture>) {
    let name = format!("hook {}", hook.script);
    let result = (|| -> Result<(bool, String, String)> {
        if Path::new(&hook.script).is_absolute()
            || hook.script.split(['/', '\\']).any(|p| p == "..")
        {
            anyhow::bail!("hook script must be a path inside the collection");
        }
        let tmp = tempfile::tempdir()?;
        let (out_path, err_path) = (tmp.path().join("out"), tmp.path().join("err"));
        let mut child = Command::new(input.root.join(&hook.script))
            .args(&hook.args)
            .current_dir(input.root)
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(&out_path)?)
            .stderr(std::fs::File::create(&err_path)?)
            .spawn()
            .with_context(|| format!("cannot run {}", hook.script))?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(serde_json::to_string(&hook_input(input))?.as_bytes());
        }
        let deadline = Instant::now() + Duration::from_secs(hook.timeout_secs);
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("timed out after {} s", hook.timeout_secs);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Ok((
            status.success(),
            std::fs::read_to_string(out_path)?,
            std::fs::read_to_string(err_path)?,
        ))
    })();
    let (ok, stdout, stderr) = match result {
        Ok(r) => r,
        Err(e) => return (vec![AssertionResult::fail(name, format!("{e:#}"))], vec![]),
    };
    let parsed: HookOutput = if stdout.trim().is_empty() {
        HookOutput::default()
    } else {
        serde_json::from_str(&stdout).unwrap_or_default()
    };
    let mut assertions: Vec<AssertionResult> = parsed
        .assertions
        .into_iter()
        .map(|a| AssertionResult {
            name: a.name,
            passed: a.passed,
            message: a.message,
        })
        .collect();
    let detail = parsed
        .message
        .or_else(|| Some(stderr.trim().to_string()).filter(|s| !s.is_empty()));
    assertions.push(if ok {
        AssertionResult::ok(name)
    } else {
        AssertionResult::fail(name, detail.unwrap_or_else(|| "script failed".into()))
    });
    let captures = parsed
        .captures
        .into_iter()
        .map(|(k, v)| Capture {
            secret: false,
            value: as_text(&v),
            name: k,
        })
        .collect();
    (assertions, captures)
}

/// Evaluates every check and capture in `test`.
pub fn evaluate(test: &TestFile, input: &EvalInput<'_>) -> Outcome {
    let mut out = Outcome::default();
    let Some(resp) = &input.raw.response else {
        return out;
    };
    let e = &test.expect;
    if let Some(spec) = &e.status {
        let items = spec.items();
        let labels: Vec<String> = items.iter().map(StatusItem::label).collect();
        let name = if labels.len() == 1 {
            format!("status is {}", labels[0])
        } else {
            format!("status in [{}]", labels.join(", "))
        };
        out.assertions
            .push(if items.iter().any(|i| i.matches(resp.status)) {
                AssertionResult::ok(name)
            } else {
                AssertionResult::fail(name, format!("got {}", resp.status))
            });
    }
    if let Some(max) = e.max_time_ms {
        let took = input.raw.timing.total_ms;
        let name = format!("time ≤ {max} ms");
        out.assertions.push(if took <= max {
            AssertionResult::ok(name)
        } else {
            AssertionResult::fail(name, format!("took {took:.1} ms"))
        });
    }
    for (header, check) in &e.headers {
        let what = Extract::Header(header.clone());
        let actual = extract(input.raw, &what).ok().flatten();
        let shown = extract(input.shown, &what).ok().flatten();
        out.assertions.extend(check_ops(
            &format!("header {header}"),
            &check.ops(),
            actual.as_ref(),
            shown.as_ref(),
            input.vars,
        ));
    }
    if let Some(schema) = &e.schema {
        out.assertions
            .push(check_schema(input.root, schema, &resp.body));
    }
    message_checks(e.body.as_ref(), &e.json, &test.capture, input, &mut out);
    if let Some(hook) = &test.hook {
        let (a, c) = run_hook(hook, input);
        out.assertions.extend(a);
        out.captures.extend(c);
    }
    out
}

/// Body, JSON, and capture checks on `input`'s response body (shared by HTTP
/// responses and WebSocket messages).
fn message_checks(
    body: Option<&Check>,
    json: &[JsonCheck],
    capture: &BTreeMap<String, CaptureSpec>,
    input: &EvalInput<'_>,
    out: &mut Outcome,
) {
    if let Some(check) = body {
        let actual = extract(input.raw, &Extract::Body).ok().flatten();
        let shown = extract(input.shown, &Extract::Body).ok().flatten();
        out.assertions.extend(check_ops(
            "body",
            &check.ops(),
            actual.as_ref(),
            shown.as_ref(),
            input.vars,
        ));
    }
    for jc in json {
        match extract(input.raw, &jc.select) {
            Ok(actual) => {
                let shown = extract(input.shown, &jc.select).ok().flatten();
                out.assertions.extend(check_ops(
                    &jc.select.label(),
                    &jc.ops,
                    actual.as_ref(),
                    shown.as_ref(),
                    input.vars,
                ));
            }
            Err(msg) => out
                .assertions
                .push(AssertionResult::fail(jc.select.label(), msg)),
        }
    }
    for (name, spec) in capture {
        let (from, secret) = spec.parts();
        let what = match Extract::parse(from) {
            Ok(w) => w,
            Err(msg) => {
                out.assertions
                    .push(AssertionResult::fail(format!("capture {name}"), msg));
                continue;
            }
        };
        match extract(input.raw, &what) {
            Ok(Some(v)) => {
                let masked = extract(input.shown, &what).ok().flatten().as_ref() != Some(&v);
                out.captures.push(Capture {
                    name: name.clone(),
                    value: as_text(&v),
                    secret: secret || masked,
                });
            }
            Ok(None) => out.assertions.push(AssertionResult::fail(
                format!("capture {name} from {}", what.label()),
                "no value found".into(),
            )),
            Err(msg) => out.assertions.push(AssertionResult::fail(
                format!("capture {name} from {}", what.label()),
                msg,
            )),
        }
    }
}

/// Checks one received WebSocket message against a `receive` step. `raw` is
/// the message as received, `shown` its redacted form (for messages).
pub fn evaluate_message(
    step: &Step,
    raw: &[u8],
    shown: &[u8],
    vars: &BTreeMap<String, String>,
    root: &Path,
    file: &Path,
) -> Outcome {
    let wrap = |body: &[u8]| Exchange {
        response: Some(crate::curlexec::ResponseRecord {
            status: 200,
            size: body.len(),
            body: body.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (raw_ex, shown_ex) = (wrap(raw), wrap(shown));
    let input = EvalInput {
        raw: &raw_ex,
        shown: &shown_ex,
        vars,
        root,
        file,
        env: None,
    };
    let mut out = Outcome::default();
    message_checks(
        step.body.as_ref(),
        &step.json,
        &step.capture,
        &input,
        &mut out,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curlexec::{ResponseRecord, Timing};

    fn exchange(status: u16, body: &str) -> Exchange {
        Exchange {
            response: Some(ResponseRecord {
                status,
                http_version: "HTTP/1.1".into(),
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/json; charset=utf-8".into(),
                    ),
                    ("X-Count".into(), "5".into()),
                ],
                size: body.len(),
                body: body.as_bytes().to_vec(),
                ..Default::default()
            }),
            timing: Timing {
                total_ms: 120.0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn run(toml_text: &str, raw: &Exchange, shown: &Exchange) -> Outcome {
        let test = TestFile::parse(toml_text).unwrap();
        let vars = BTreeMap::from([("expected_name".to_string(), "Ada".to_string())]);
        let root = std::env::temp_dir();
        evaluate(
            &test,
            &EvalInput {
                raw,
                shown,
                vars: &vars,
                root: &root,
                file: Path::new("x.curl"),
                env: None,
            },
        )
    }

    fn failures(o: &Outcome) -> Vec<String> {
        o.assertions
            .iter()
            .filter(|a| !a.passed)
            .map(|a| format!("{}: {}", a.name, a.message.clone().unwrap_or_default()))
            .collect()
    }

    const BODY: &str =
        r#"{"id":7,"name":"Ada","tags":["a","b"],"token":"s3cret","nested":{"ok":true}}"#;

    #[test]
    fn passing_checks() {
        let ex = exchange(201, BODY);
        let o = run(
            r#"
[expect]
status = ["2xx", 304]
max_time_ms = 500
[expect.headers]
Content-Type = { matches = "^application/json" }
X-Count = 5
X-Missing = { exists = false }
[expect.body]
contains = "Ada"
[[expect.json]]
path = "$.id"
eq = 7
gte = 7
type = "integer"
[[expect.json]]
path = "$.name"
eq = "{{expected_name}}"
[[expect.json]]
path = "$.tags"
len = 2
contains = "b"
[[expect.json]]
jq = ".nested.ok"
eq = true
[[expect.json]]
path = "$.nothing"
exists = false
"#,
            &ex,
            &ex,
        );
        assert!(failures(&o).is_empty(), "{:?}", failures(&o));
        assert_eq!(o.assertions.len(), 14);
        assert_eq!(o.assertions[0].name, "status in [2xx, 304]");
    }

    #[test]
    fn failing_checks_explain_and_hide_secrets() {
        let raw = exchange(404, BODY);
        let shown = exchange(404, &BODY.replace("s3cret", "[REDACTED]"));
        let o = run(
            "[expect]\nstatus = 200\nmax_time_ms = 50\n[[expect.json]]\npath = \"$.token\"\neq = \"other\"\n[[expect.json]]\npath = \"$.missing\"\neq = 1\n",
            &raw,
            &shown,
        );
        let f = failures(&o);
        assert_eq!(f[0], "status is 200: got 404");
        assert_eq!(f[1], "time ≤ 50 ms: took 120.0 ms");
        assert_eq!(f[2], "$.token eq \"other\": got \"[REDACTED]\"");
        assert_eq!(f[3], "$.missing: no value found");
        assert!(!f.join(" ").contains("s3cret"));
    }

    #[test]
    fn captures_infer_secrets_from_redaction() {
        let raw = exchange(200, BODY);
        let shown = exchange(200, &BODY.replace("s3cret", "[REDACTED]"));
        let o = run(
            "[capture]\nuser_id = \"$.id\"\ntok = \"$.token\"\nct = \"header:content-type\"\nre = \"regex:\\\"name\\\":\\\"(\\\\w+)\\\"\"\nmissing = \"$.nope\"\n",
            &raw,
            &shown,
        );
        let caps: BTreeMap<_, _> = o
            .captures
            .iter()
            .map(|c| (c.name.as_str(), (c.value.as_str(), c.secret)))
            .collect();
        assert_eq!(caps["user_id"], ("7", false));
        assert_eq!(caps["tok"], ("s3cret", true));
        assert_eq!(caps["ct"].0, "application/json; charset=utf-8");
        assert_eq!(caps["re"].0, "Ada");
        assert_eq!(
            failures(&o),
            vec!["capture missing from $.nope: no value found"]
        );
    }

    #[test]
    fn rejects_bad_sidecars() {
        assert!(TestFile::parse("[expect]\nstatuss = 200\n").is_err());
        assert!(TestFile::parse("[expect]\nstatus = \"2x\"\n").is_err());
        assert!(TestFile::parse("[[expect.json]]\neq = 1\n").is_err());
        assert!(TestFile::parse("[[expect.json]]\npath = \"$.a\"\neqq = 1\n").is_err());
        assert!(TestFile::parse("[capture]\nx = \"nonsense\"\n").is_err());
        assert!(TestFile::parse("[expect.headers]\nA = { matchs = \"x\" }\n").is_err());
        assert_eq!(
            sidecar_path(Path::new("a/b.curl")),
            PathBuf::from("a/b.test.toml")
        );
    }

    #[cfg(unix)]
    #[test]
    fn hook_script_can_assert_and_capture() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("hook.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in *Ada*) echo '{\"captures\":{\"seen\":\"yes\"},\"assertions\":[{\"name\":\"saw Ada\",\"passed\":true}]}' ;; *) echo nope >&2; exit 1 ;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let test = TestFile::parse("[hook]\nscript = \"hook.sh\"\n").unwrap();
        let vars = BTreeMap::new();
        let ex = exchange(200, BODY);
        let input = EvalInput {
            raw: &ex,
            shown: &ex,
            vars: &vars,
            root: tmp.path(),
            file: Path::new("x.curl"),
            env: None,
        };
        let o = evaluate(&test, &input);
        assert!(failures(&o).is_empty(), "{:?}", failures(&o));
        assert_eq!(o.captures[0].value, "yes");
        let ex2 = exchange(200, "{}");
        let o = evaluate(
            &test,
            &EvalInput {
                raw: &ex2,
                shown: &ex2,
                ..input
            },
        );
        assert_eq!(failures(&o), vec!["hook hook.sh: nope"]);
    }
}
