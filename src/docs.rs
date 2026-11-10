//! `curly docs`: a static reference for a collection, as one self-contained
//! HTML file (inline CSS, no scripts or external assets) or Markdown.
//!
//! Docs show variable *names*; values only for non-secrets. Bodies and
//! headers are shown as written in the request files (`{{templates}}`), and
//! example responses come from `*.example.json` files, which are saved from
//! redacted history.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;
use serde_json::Value;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::SyntaxSet;

use crate::assertions::{Check, Ops, TestFile};
use crate::curlconf::RequestSpec;
use crate::folder;
use crate::project::Project;
use crate::vars::Layers;

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);
static THEME: LazyLock<Theme> = LazyLock::new(|| {
    ThemeSet::load_defaults()
        .themes
        .remove("InspiredGitHub")
        .unwrap_or_default()
});

/// Files larger than this are referenced instead of inlined.
const MAX_INLINE: usize = 20 * 1024;

/// A code block: language hint and text.
#[derive(Debug, Clone, PartialEq)]
pub struct Code {
    /// Short heading (`Request body`, `Query`, ...).
    pub title: String,
    /// Language (`json`, `graphql`, `sh`, `text`).
    pub lang: String,
    /// Content.
    pub text: String,
}

/// One documented request.
#[derive(Debug, Clone, PartialEq)]
pub struct DocRequest {
    /// Collection-relative file.
    pub file: PathBuf,
    /// Anchor id.
    pub anchor: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// `HTTP`, `GraphQL`, `WebSocket`, or `gRPC`.
    pub protocol: String,
    /// Method (or `RPC`/`WS`).
    pub method: String,
    /// URL template as written.
    pub url: String,
    /// Header templates as written.
    pub headers: Vec<String>,
    /// Bodies, documents, messages, and scripts.
    pub code: Vec<Code>,
    /// Human-readable checks from the test sidecar.
    pub checks: Vec<String>,
    /// Saved example responses.
    pub examples: Vec<Code>,
    /// Equivalent plain curl command (`.curl` only).
    pub curl: Option<Code>,
}

/// A folder and its requests, in run order.
#[derive(Debug, Clone, PartialEq)]
pub struct DocFolder {
    /// Collection-relative folder (empty = root).
    pub path: PathBuf,
    /// Leading comment of `_folder.toml`.
    pub description: Option<String>,
    /// Auth summary from `[auth]`.
    pub auth: Option<String>,
    /// Requests.
    pub requests: Vec<DocRequest>,
}

/// A variable in the variables table.
#[derive(Debug, Clone, PartialEq)]
pub struct DocVar {
    /// Name.
    pub name: String,
    /// Value, or `None` for secrets.
    pub value: Option<String>,
    /// Where it is defined.
    pub location: String,
}

/// The whole document.
#[derive(Debug, Clone, PartialEq)]
pub struct Doc {
    /// Collection name.
    pub title: String,
    /// Environment the variables come from.
    pub env: Option<String>,
    /// Variables.
    pub vars: Vec<DocVar>,
    /// Folders.
    pub folders: Vec<DocFolder>,
}

/// Anchor id for a path (`users/get-user.curl` -> `users-get-user-curl`).
fn anchor(path: &Path) -> String {
    path.display()
        .to_string()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Describes an operator table as phrases (`eq "x"`, `has length 2`).
fn ops_phrases(ops: &Ops) -> Vec<String> {
    let show = |v: &Value| serde_json::to_string(v).unwrap_or_default();
    let mut out = Vec::new();
    if let Some(v) = &ops.eq {
        out.push(format!("equals {}", show(v)));
    }
    if let Some(v) = &ops.ne {
        out.push(format!("is not {}", show(v)));
    }
    for (label, v) in [
        ("> ", ops.gt),
        ("≥ ", ops.gte),
        ("< ", ops.lt),
        ("≤ ", ops.lte),
    ] {
        if let Some(v) = v {
            out.push(format!("{label}{v}"));
        }
    }
    if let Some(v) = &ops.contains {
        out.push(format!("contains {}", show(v)));
    }
    if let Some(v) = &ops.matches {
        out.push(format!("matches /{v}/"));
    }
    if let Some(v) = &ops.kind {
        out.push(format!("is {v}"));
    }
    if let Some(v) = ops.len {
        out.push(format!("has length {v}"));
    }
    match ops.exists {
        Some(true) => out.push("exists".into()),
        Some(false) => out.push("is absent".into()),
        None if out.is_empty() => out.push("exists".into()),
        None => {}
    }
    out
}

fn check_phrase(subject: &str, check: &Check) -> String {
    format!("{subject} {}", ops_phrases(&check.ops()).join(", "))
}

/// Human-readable list of what a sidecar checks and captures.
pub fn describe_test(t: &TestFile) -> Vec<String> {
    let e = &t.expect;
    let mut out = Vec::new();
    if let Some(s) = &e.status {
        let items: Vec<String> = s.items().iter().map(|i| i.label()).collect();
        out.push(format!("status is {}", items.join(" or ")));
    }
    if let Some(ms) = e.max_time_ms {
        out.push(format!("responds within {ms} ms"));
    }
    if let Some(schema) = &e.schema {
        out.push(format!("body matches the JSON Schema {schema}"));
    }
    for (name, check) in &e.headers {
        out.push(check_phrase(&format!("header {name}"), check));
    }
    if let Some(check) = &e.body {
        out.push(check_phrase("body", check));
    }
    for jc in &e.json {
        out.push(format!(
            "{} {}",
            jc.select.label(),
            ops_phrases(&jc.ops).join(", ")
        ));
    }
    for (name, spec) in &t.capture {
        out.push(format!("captures `{name}` from {}", spec.parts().0));
    }
    if let Some(h) = &t.hook {
        out.push(format!("runs the hook {}", h.script));
    }
    out
}

/// WebSocket steps as a readable script.
fn describe_steps(t: &TestFile) -> Option<Code> {
    if t.step.is_empty() {
        return None;
    }
    let mut text = String::new();
    for (i, s) in t.step.iter().enumerate() {
        let n = i + 1;
        let action = if let Some(m) = &s.send {
            format!("send {m}")
        } else if let Some(f) = &s.send_file {
            format!("send the bytes of {f}")
        } else if let Some(ms) = s.receive {
            let mut parts: Vec<String> =
                s.body.iter().map(|c| check_phrase("message", c)).collect();
            parts.extend(
                s.json
                    .iter()
                    .map(|j| format!("{} {}", j.select.label(), ops_phrases(&j.ops).join(", "))),
            );
            parts.extend(
                s.capture
                    .iter()
                    .map(|(k, v)| format!("capture `{k}` from {}", v.parts().0)),
            );
            let detail = if parts.is_empty() {
                String::new()
            } else {
                format!(": {}", parts.join("; "))
            };
            format!("receive within {ms} ms{detail}")
        } else if let Some(ms) = s.sleep_ms {
            format!("wait {ms} ms")
        } else {
            "close".into()
        };
        let _ = writeln!(text, "{n}. {action}");
    }
    Some(Code {
        title: "Script".into(),
        lang: "text".into(),
        text,
    })
}

/// Reads a collection file for inlining; JSON is pretty-printed.
fn inline_file(project: &Project, rel: &str) -> Option<(String, String)> {
    let path = project.root.join(rel);
    let meta = std::fs::metadata(&path).ok()?;
    if meta.len() as usize > MAX_INLINE {
        return Some(("text".into(), format!("(see {rel}, {} bytes)", meta.len())));
    }
    let text = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => Some((
            "json".into(),
            serde_json::to_string_pretty(&v).unwrap_or(text),
        )),
        Err(_) => Some((
            if rel.ends_with(".graphql") {
                "graphql"
            } else {
                "text"
            }
            .into(),
            text,
        )),
    }
}

/// A body value: an `@file` reference is inlined, JSON literals are pretty-printed.
fn body_code(project: &Project, title: &str, value: &str) -> Code {
    if let Some(file) = value.strip_prefix('@')
        && let Some((lang, text)) = inline_file(project, file)
    {
        return Code {
            title: format!("{title} ({file})"),
            lang,
            text,
        };
    }
    match serde_json::from_str::<Value>(value) {
        Ok(v) if v.is_object() || v.is_array() => Code {
            title: title.into(),
            lang: "json".into(),
            text: serde_json::to_string_pretty(&v).unwrap_or_default(),
        },
        _ => Code {
            title: title.into(),
            lang: "text".into(),
            text: value.into(),
        },
    }
}

/// Builds the documentation entry for one request.
fn request_doc(project: &Project, rel: &Path, env: Option<&str>) -> Result<DocRequest> {
    let spec = RequestSpec::load(&project.root, rel)?;
    let test = TestFile::load_for(&project.root, rel).ok().flatten();
    let ext = rel.extension().and_then(|e| e.to_str()).unwrap_or_default();
    let graphql = crate::graphql::graphql_files(&spec);
    let (protocol, method) = match (ext, &graphql) {
        ("ws", _) => ("WebSocket", "WS".to_string()),
        ("grpc", _) => ("gRPC", "RPC".to_string()),
        (_, Some(_)) => ("GraphQL", spec.method.clone()),
        _ => ("HTTP", spec.method.clone()),
    };
    let mut code = Vec::new();
    match &graphql {
        Some(g) => {
            if let Some((lang, text)) = inline_file(project, &g.document.display().to_string()) {
                code.push(Code {
                    title: format!("Query ({})", g.document.display()),
                    lang,
                    text,
                });
            }
            if let Some(v) = &g.variables
                && let Some((lang, text)) = inline_file(project, &v.display().to_string())
            {
                code.push(Code {
                    title: format!("Variables ({})", v.display()),
                    lang,
                    text,
                });
            }
        }
        None => {
            let label = if ext == "grpc" {
                "Message"
            } else {
                "Request body"
            };
            for e in spec.config.entries.iter().filter(|e| {
                crate::curlconf::BODY_OPTIONS.contains(&e.base_name()) && e.base_name() != "get"
            }) {
                code.push(body_code(
                    project,
                    label,
                    e.value.as_deref().unwrap_or_default(),
                ));
            }
        }
    }
    if let Some(steps) = test.as_ref().and_then(describe_steps) {
        code.push(steps);
    }
    let mut examples = Vec::new();
    let dir = project.root.join(rel.parent().unwrap_or(Path::new("")));
    let stem = rel
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!("{stem}.")) && n.ends_with("example.json"))
        .collect();
    names.sort();
    for name in names {
        let rel_example = rel.with_file_name(&name).display().to_string();
        if let Ok(v) = serde_json::from_str::<Value>(
            &std::fs::read_to_string(dir.join(&name)).unwrap_or_default(),
        ) {
            let status = v["status"].as_u64().unwrap_or(0);
            let body = &v["body"];
            let (lang, text) = match body {
                Value::String(s) => ("text".to_string(), s.clone()),
                other => (
                    "json".to_string(),
                    serde_json::to_string_pretty(other).unwrap_or_default(),
                ),
            };
            examples.push(Code {
                title: format!("{status} ({rel_example})"),
                lang,
                text,
            });
        }
    }
    let curl = if ext == "curl" {
        crate::request::plain_command(project, rel, env, &[])
            .ok()
            .map(|(cmd, exports)| {
                let mut text = exports.join("\n");
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&cmd);
                Code {
                    title: "Plain curl (from the collection root)".into(),
                    lang: "sh".into(),
                    text,
                }
            })
    } else {
        None
    };
    Ok(DocRequest {
        file: rel.to_path_buf(),
        anchor: anchor(rel),
        title: spec.title(),
        description: spec.meta.description.clone(),
        tags: spec.meta.tags.clone(),
        protocol: protocol.into(),
        method,
        url: spec.url.clone().unwrap_or_default(),
        headers: spec.headers.clone(),
        code,
        checks: test.as_ref().map(describe_test).unwrap_or_default(),
        examples,
        curl,
    })
}

/// Leading `#` comment lines of a `_folder.toml`.
fn folder_description(project: &Project, dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(project.root.join(dir).join(folder::FOLDER_FILE)).ok()?;
    let lines: Vec<&str> = text
        .lines()
        .take_while(|l| l.starts_with('#'))
        .map(|l| l.trim_start_matches('#').trim())
        .collect();
    let d = lines.join(" ").trim().to_string();
    (!d.is_empty()).then_some(d)
}

/// One-line summary of an `[auth]` table (no secrets: templates only).
fn auth_summary(project: &Project, dir: &Path) -> Option<String> {
    let cfg = folder::load(&project.root.join(dir)).ok()??;
    let a = cfg.auth?;
    if a.kind == crate::oauth::AuthKind::None {
        return Some("no auth (stops inheritance)".into());
    }
    let mut s = format!(
        "OAuth 2.0 {} → `{{{{{}}}}}`",
        a.flow.map(|f| f.as_str()).unwrap_or("?"),
        a.token_var
    );
    if let Some(t) = &a.token_url {
        let _ = write!(s, "; token URL `{t}`");
    }
    if !a.scopes.is_empty() {
        let _ = write!(s, "; scopes {}", a.scopes.join(" "));
    }
    Some(s)
}

/// Collects documentation for `targets` (collection-relative files or folders).
pub fn collect(project: &Project, targets: &[PathBuf], env: Option<&str>) -> Result<Doc> {
    let files = crate::runner::plan(project, targets)?;
    let mut folders: Vec<DocFolder> = Vec::new();
    for rel in &files {
        let dir = rel.parent().map(Path::to_path_buf).unwrap_or_default();
        if folders.last().is_none_or(|f| f.path != dir) {
            folders.push(DocFolder {
                description: folder_description(project, &dir),
                auth: auth_summary(project, &dir),
                path: dir,
                requests: vec![],
            });
        }
        let doc = request_doc(project, rel, env)?;
        folders.last_mut().expect("folder").requests.push(doc);
    }
    let mut layers = Layers::default();
    for rel in &files {
        layers.folder.extend(folder::folder_vars(project, rel)?);
    }
    let ctx = crate::vars::VarContext::build(project, env, &layers, None)?;
    let mut vars: Vec<DocVar> = ctx
        .effective(&project.root)
        .into_iter()
        .map(|(name, r)| DocVar {
            name,
            value: if r.secret { None } else { r.value },
            location: r.location,
        })
        .collect();
    let index_file = project
        .root
        .join(crate::project::STATE_DIR)
        .join("secrets.json");
    if let (Some(env_name), true) = (
        ctx.env.as_ref().map(|e| e.name.clone()),
        index_file.is_file(),
    ) {
        for name in crate::secrets::SecretIndex::load(project)?.names(&env_name) {
            if !vars.iter().any(|v| v.name == name) {
                vars.push(DocVar {
                    name,
                    value: None,
                    location: "secret store".into(),
                });
            }
        }
        vars.sort_by(|a, b| a.name.cmp(&b.name));
    }
    let title = if project.config.project.name.is_empty() {
        "API collection".to_string()
    } else {
        project.config.project.name.clone()
    };
    Ok(Doc {
        title,
        env: ctx.env.map(|e| e.name),
        vars,
        folders,
    })
}

/// Markdown rendering.
pub fn render_markdown(doc: &Doc) -> String {
    let mut out = format!("# {}\n\n", doc.title);
    let _ = writeln!(
        out,
        "Generated by `curly docs`. Run any `.curl` request with plain curl from the collection root.\n"
    );
    out.push_str("## Contents\n\n");
    for f in &doc.folders {
        let _ = writeln!(out, "- **{}**", folder_title(&f.path));
        for r in &f.requests {
            let _ = writeln!(
                out,
                "  - [{}](#{}) `{} {}`",
                r.title,
                r.anchor,
                r.method,
                r.file.display()
            );
        }
    }
    let _ = writeln!(
        out,
        "\n## Variables{}\n",
        doc.env
            .as_ref()
            .map(|e| format!(" (environment `{e}`)"))
            .unwrap_or_default()
    );
    out.push_str("| Name | Value | Defined in |\n|---|---|---|\n");
    for v in &doc.vars {
        let value = v
            .value
            .as_deref()
            .map(|x| format!("`{}`", x.replace('|', "\\|")))
            .unwrap_or_else(|| "*secret*".into());
        let _ = writeln!(out, "| `{}` | {value} | {} |", v.name, v.location);
    }
    for f in &doc.folders {
        let _ = writeln!(out, "\n## {}\n", folder_title(&f.path));
        if let Some(d) = &f.description {
            let _ = writeln!(out, "{d}\n");
        }
        if let Some(a) = &f.auth {
            let _ = writeln!(out, "**Auth:** {a}\n");
        }
        for r in &f.requests {
            let _ = writeln!(out, "<a id=\"{}\"></a>\n### {}\n", r.anchor, r.title);
            let _ = writeln!(
                out,
                "`{}` **{}** `{}` — `{}`\n",
                r.protocol,
                r.method,
                r.url,
                r.file.display()
            );
            if let Some(d) = &r.description {
                let _ = writeln!(out, "{d}\n");
            }
            if !r.tags.is_empty() {
                let _ = writeln!(
                    out,
                    "Tags: {}\n",
                    r.tags
                        .iter()
                        .map(|t| format!("`{t}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if !r.headers.is_empty() {
                out.push_str("**Headers**\n\n");
                for h in &r.headers {
                    let _ = writeln!(out, "- `{h}`");
                }
                out.push('\n');
            }
            for c in r.code.iter().chain(r.curl.iter()) {
                let _ = writeln!(
                    out,
                    "**{}**\n\n```{}\n{}\n```\n",
                    c.title,
                    c.lang,
                    c.text.trim_end()
                );
            }
            if !r.checks.is_empty() {
                out.push_str("**Checks**\n\n");
                for c in &r.checks {
                    let _ = writeln!(out, "- {c}");
                }
                out.push('\n');
            }
            for e in &r.examples {
                let _ = writeln!(
                    out,
                    "**Example response {}**\n\n```{}\n{}\n```\n",
                    e.title,
                    e.lang,
                    e.text.trim_end()
                );
            }
        }
    }
    out
}

fn folder_title(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        "Collection root".into()
    } else {
        format!("{}/", path.display())
    }
}

/// Escapes text for HTML.
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A highlighted (or plain, escaped) `<pre>` block.
fn code_html(c: &Code) -> String {
    let ext = c.lang.as_str();
    let highlighted = SYNTAXES.find_syntax_by_extension(ext).and_then(|syntax| {
        syntect::html::highlighted_html_for_string(&c.text, &SYNTAXES, syntax, &THEME).ok()
    });
    let pre = highlighted.unwrap_or_else(|| format!("<pre>{}</pre>", escape(&c.text)));
    format!(
        "<figure><figcaption>{}</figcaption>{pre}</figure>\n",
        escape(&c.title)
    )
}

const CSS: &str = "body{font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;color:#1f2328;background:#fff}\
nav{position:fixed;top:0;bottom:0;width:280px;overflow:auto;padding:16px;border-right:1px solid #d0d7de;background:#f6f8fa;box-sizing:border-box}\
nav a{display:block;color:#0969da;text-decoration:none;padding:1px 0;font-size:14px}nav h2{font-size:13px;margin:14px 0 4px;color:#59636e}\
main{margin-left:280px;padding:24px 40px;max-width:980px}h1{margin-top:0}section.request{border-top:1px solid #d0d7de;padding-top:12px;margin-top:28px}\
.line{font-family:ui-monospace,Menlo,monospace;font-size:14px}.method{font-weight:700;margin-right:6px}.proto{font-size:12px;padding:1px 6px;border-radius:10px;background:#ddf4ff;color:#0550ae;margin-right:6px}\
.tag{font-size:12px;padding:1px 6px;border-radius:10px;background:#eef1f4;margin-right:4px}figure{margin:12px 0}figcaption{font-size:13px;font-weight:600;margin-bottom:4px}\
pre{padding:10px;border:1px solid #d0d7de;border-radius:6px;overflow:auto;font-size:13px;background:#f6f8fa}table{border-collapse:collapse}td,th{border:1px solid #d0d7de;padding:4px 8px;text-align:left;font-size:14px}\
code{font-family:ui-monospace,Menlo,monospace;font-size:13px}.secret{color:#59636e;font-style:italic}.file{color:#59636e;font-size:13px}";

/// Self-contained HTML rendering (well-formed XHTML-style markup).
pub fn render_html(doc: &Doc) -> String {
    let mut nav = String::new();
    let mut main = String::new();
    let _ = write!(
        main,
        "<h1>{}</h1>\n<p>Generated by <code>curly docs</code>. Run any <code>.curl</code> request with plain curl from the collection root.</p>\n",
        escape(&doc.title)
    );
    let _ = write!(
        main,
        "<h2 id=\"variables\">Variables{}</h2>\n<table><tr><th>Name</th><th>Value</th><th>Defined in</th></tr>\n",
        doc.env
            .as_ref()
            .map(|e| format!(" (environment <code>{}</code>)", escape(e)))
            .unwrap_or_default()
    );
    for v in &doc.vars {
        let value = v
            .value
            .as_deref()
            .map(|x| format!("<code>{}</code>", escape(x)))
            .unwrap_or_else(|| "<span class=\"secret\">secret</span>".into());
        let _ = writeln!(
            main,
            "<tr><td><code>{}</code></td><td>{value}</td><td>{}</td></tr>",
            escape(&v.name),
            escape(&v.location)
        );
    }
    main.push_str("</table>\n");
    let _ = writeln!(nav, "<a href=\"#variables\">Variables</a>");
    for f in &doc.folders {
        let fid = format!("folder-{}", anchor(&f.path));
        let _ = writeln!(nav, "<h2>{}</h2>", escape(&folder_title(&f.path)));
        let _ = writeln!(
            main,
            "<h2 id=\"{fid}\">{}</h2>",
            escape(&folder_title(&f.path))
        );
        if let Some(d) = &f.description {
            let _ = writeln!(main, "<p>{}</p>", escape(d));
        }
        if let Some(a) = &f.auth {
            let _ = writeln!(main, "<p><strong>Auth:</strong> {}</p>", escape(a));
        }
        for r in &f.requests {
            let _ = writeln!(nav, "<a href=\"#{}\">{}</a>", r.anchor, escape(&r.title));
            let _ = writeln!(
                main,
                "<section class=\"request\" id=\"{}\">\n<h3>{}</h3>",
                r.anchor,
                escape(&r.title)
            );
            let _ = writeln!(
                main,
                "<p class=\"line\"><span class=\"proto\">{}</span><span class=\"method\">{}</span>{} <span class=\"file\">{}</span></p>",
                escape(&r.protocol),
                escape(&r.method),
                escape(&r.url),
                escape(&r.file.display().to_string())
            );
            if let Some(d) = &r.description {
                let _ = writeln!(main, "<p>{}</p>", escape(d).replace('\n', "<br />"));
            }
            if !r.tags.is_empty() {
                let tags: String = r
                    .tags
                    .iter()
                    .map(|t| format!("<span class=\"tag\">{}</span>", escape(t)))
                    .collect();
                let _ = writeln!(main, "<p>{tags}</p>");
            }
            if !r.headers.is_empty() {
                main.push_str("<p><strong>Headers</strong></p><ul>");
                for h in &r.headers {
                    let _ = write!(main, "<li><code>{}</code></li>", escape(h));
                }
                main.push_str("</ul>\n");
            }
            for c in r.code.iter().chain(r.curl.iter()) {
                main.push_str(&code_html(c));
            }
            if !r.checks.is_empty() {
                main.push_str("<p><strong>Checks</strong></p><ul>");
                for c in &r.checks {
                    let _ = write!(main, "<li>{}</li>", escape(c));
                }
                main.push_str("</ul>\n");
            }
            for e in &r.examples {
                main.push_str(&code_html(&Code {
                    title: format!("Example response {}", e.title),
                    ..e.clone()
                }));
            }
            main.push_str("</section>\n");
        }
    }
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n<title>{}</title>\n<style>{CSS}</style>\n</head>\n<body>\n<nav>\n{nav}</nav>\n<main>\n{main}</main>\n</body>\n</html>\n",
        escape(&doc.title)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_tests() {
        let t = TestFile::parse("[expect]\nstatus = [200, \"2xx\"]\nmax_time_ms = 500\nschema = \"s.json\"\n[expect.headers]\nX = { matches = \"^a\" }\n[[expect.json]]\npath = \"$.n\"\ngte = 2\nlen = 3\n[capture]\nid = \"$.id\"\n").unwrap();
        assert_eq!(
            describe_test(&t),
            vec![
                "status is 200 or 2xx",
                "responds within 500 ms",
                "body matches the JSON Schema s.json",
                "header X matches /^a/",
                "$.n ≥ 2, has length 3",
                "captures `id` from $.id"
            ]
        );
        let ws = TestFile::parse("[[step]]\nsend = \"hi\"\n[[step]]\nreceive = 100\n[[step.json]]\npath = \"$.a\"\neq = 1\n[[step]]\nclose = true\n").unwrap();
        assert_eq!(
            describe_steps(&ws).unwrap().text,
            "1. send hi\n2. receive within 100 ms: $.a equals 1\n3. close\n"
        );
    }

    #[test]
    fn escapes_html() {
        assert_eq!(
            escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(
            anchor(Path::new("users/get-user.curl")),
            "users-get-user-curl"
        );
    }
}
