//! Generates a folder of request files, example payloads, test sidecars, and
//! JSON Schemas from an OpenAPI/Swagger document.
//!
//! Every generated `.curl` file is plain curl config. Values the spec does not
//! pin down (base URL, parameters, credentials) become `{{variables}}` defined
//! in the environment file; credentials are imported from the shell or the
//! secret store (`variable = %NAME=`) and never written as values.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::model::{Api, Body, Operation, ParamIn, Scheme, Spec, normalize};
use super::schema::{Converter, Direction, Examples};
use crate::assertions::TEST_SUFFIX;
use crate::curlconf::quote;
use crate::folder::FOLDER_FILE;
use crate::project::{self, InitOptions, Project};
use crate::vars::SecretNames;

/// Options for [`import`].
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Spec path or `http(s)://` URL.
    pub source: String,
    /// Output folder (default: `<cwd>/<api-slug>`).
    pub out: Option<PathBuf>,
    /// Environment to add variables to.
    pub env: String,
    /// Overwrite existing generated files.
    pub force: bool,
    /// curl binary used to download URLs.
    pub curl: String,
    /// Directory relative paths are resolved against.
    pub cwd: PathBuf,
}

/// What [`import`] did.
#[derive(Debug, Clone, Default)]
pub struct ImportSummary {
    /// API title.
    pub title: String,
    /// Collection root.
    pub root: PathBuf,
    /// Output folder relative to the root.
    pub out: PathBuf,
    /// Whether a new collection was created.
    pub new_collection: bool,
    /// Number of operations imported.
    pub operations: usize,
    /// Files written.
    pub created: Vec<PathBuf>,
    /// Files left alone because they existed.
    pub skipped: Vec<PathBuf>,
    /// Environment file (collection-relative).
    pub env_file: PathBuf,
    /// Variables added to the environment file.
    pub env_added: Vec<String>,
    /// Secret variables the user must provide.
    pub secrets: Vec<String>,
    /// Things that could not be generated fully.
    pub warnings: Vec<String>,
}

/// Lowercase kebab-case slug (`getPetById` -> `get-pet-by-id`).
pub fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && prev_lower {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        } else {
            if !out.ends_with('-') {
                out.push('-');
            }
            prev_lower = false;
        }
    }
    let s = out.trim_matches('-').to_string();
    if s.is_empty() { "api".into() } else { s }
}

/// A valid curl variable name (`X-Request-ID` -> `X_Request_ID`).
pub fn var_name(s: &str) -> String {
    let v: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if v.is_empty() { "param".into() } else { v }
}

/// SCREAMING_SNAKE form (`bearerAuth` -> `BEARER_AUTH`).
fn upper_snake(s: &str) -> String {
    slug(s).replace('-', "_").to_ascii_uppercase()
}

/// String form of an example value for a variable.
fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(value_text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

fn is_json_type(ct: &str) -> bool {
    ct.starts_with("application/json") || ct.contains("+json")
}

/// Reads a spec from a file or downloads it with curl.
fn fetch(source: &str, curl: &str, cwd: &Path) -> Result<String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let out = Command::new(curl)
            .args(["-sSfL", "--max-time", "30", source])
            .output()
            .with_context(|| format!("running {curl}"))?;
        if !out.status.success() {
            bail!(
                "downloading {source} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        return String::from_utf8(out.stdout).context("spec is not UTF-8");
    }
    let path = cwd.join(source.strip_prefix("file://").unwrap_or(source));
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// Base URL for the environment; relative server URLs are resolved against
/// the spec URL, or `http://localhost` for local files.
fn base_url(api: &Api, source: &str) -> String {
    let url = api
        .servers
        .first()
        .map(|(u, _)| u.clone())
        .unwrap_or_else(|| "/".into());
    let url = if url.contains("://") {
        url
    } else {
        let origin = source
            .split_once("://")
            .map(|(scheme, rest)| {
                format!("{scheme}://{}", rest.split('/').next().unwrap_or_default())
            })
            .unwrap_or_else(|| "http://localhost".into());
        format!(
            "{origin}{}",
            if url.starts_with('/') {
                url
            } else {
                format!("/{url}")
            }
        )
    };
    url.trim_end_matches('/').to_string()
}

/// A variable the environment file should define.
#[derive(Debug, Clone)]
struct EnvVar {
    /// Literal value, or `None` for a secret imported from the shell/secret store.
    value: Option<String>,
    /// Comment written above it.
    comment: Option<String>,
}

/// Collects everything generated for one run of the importer.
struct Generator<'a> {
    spec: &'a Spec,
    api: &'a Api,
    secrets: SecretNames,
    root: PathBuf,
    out_rel: PathBuf,
    force: bool,
    spec_file: String,
    env_vars: BTreeMap<String, EnvVar>,
    env_order: Vec<String>,
    summary: ImportSummary,
}

impl Generator<'_> {
    fn add_var(&mut self, name: &str, value: Option<String>, comment: Option<String>) {
        if !self.env_vars.contains_key(name) {
            self.env_order.push(name.to_string());
            self.env_vars
                .insert(name.to_string(), EnvVar { value, comment });
        }
    }

    /// Writes `rel` (collection-relative) unless it exists and `force` is off.
    fn write(&mut self, rel: &Path, contents: &str) -> Result<()> {
        let abs = self.root.join(rel);
        if abs.exists() && !self.force {
            self.summary.skipped.push(rel.to_path_buf());
            return Ok(());
        }
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, contents).with_context(|| format!("writing {}", abs.display()))?;
        self.summary.created.push(rel.to_path_buf());
        Ok(())
    }

    /// Variable holding a credential for scheme `name`, made to look secret.
    fn secret_var(&mut self, scheme: &str, suffix: &str, comment: String) -> String {
        let base = upper_snake(scheme);
        let name = if self.secrets.is_secret(&base) && suffix != "_USER" {
            base
        } else {
            format!("{base}{suffix}")
        };
        if suffix == "_USER" {
            self.add_var(&name, Some(String::new()), Some(comment));
        } else {
            self.add_var(&name, None, Some(comment));
            if !self.summary.secrets.contains(&name) {
                self.summary.secrets.push(name.clone());
            }
        }
        name
    }

    /// Curl lines and query parts for the first security alternative of `op`.
    fn auth_lines(
        &mut self,
        op: &Operation,
        lines: &mut Vec<String>,
        query: &mut Vec<String>,
        cookies: &mut Vec<String>,
    ) {
        let alternatives = self.api.security_for(op).to_vec();
        let Some(first) = alternatives.first() else {
            return;
        };
        if alternatives.len() > 1 {
            let others: Vec<String> = alternatives[1..]
                .iter()
                .map(|a| a.keys().cloned().collect::<Vec<_>>().join(" + "))
                .collect();
            lines.push(format!("# Other accepted auth: {}", others.join(", ")));
        }
        for (scheme_name, scopes) in first {
            let Some(scheme) = self.api.schemes.get(scheme_name).cloned() else {
                self.summary.warnings.push(format!(
                    "{} {}: unknown security scheme `{scheme_name}`",
                    op.method, op.path
                ));
                continue;
            };
            match scheme {
                Scheme::ApiKey { name, location } => {
                    let var = self.secret_var(
                        scheme_name,
                        "_API_KEY",
                        format!("API key for `{scheme_name}` ({name})"),
                    );
                    match location {
                        ParamIn::Header => lines.push(format!(
                            "expand-header = {}",
                            quote(&format!("{name}: {{{{{var}}}}}"))
                        )),
                        ParamIn::Query => query.push(format!("{name}={{{{{var}:url}}}}")),
                        ParamIn::Cookie => cookies.push(format!("{name}={{{{{var}}}}}")),
                        ParamIn::Path => {}
                    }
                }
                Scheme::Basic => {
                    let user = self.secret_var(
                        scheme_name,
                        "_USER",
                        format!("Basic auth user for `{scheme_name}`"),
                    );
                    let pass = self.secret_var(
                        scheme_name,
                        "_PASSWORD",
                        format!("Basic auth password for `{scheme_name}`"),
                    );
                    lines.push(format!(
                        "expand-user = {}",
                        quote(&format!("{{{{{user}}}}}:{{{{{pass}}}}}"))
                    ));
                }
                Scheme::Bearer | Scheme::OAuth2 { .. } | Scheme::OpenIdConnect { .. } => {
                    let mut comment = format!("Bearer token for `{scheme_name}`");
                    if let Scheme::OAuth2 { flows } = &scheme {
                        for f in flows {
                            let _ = write!(
                                comment,
                                "\n# OAuth 2.0 {} flow: authorize {} token {} scopes {}",
                                f.kind,
                                f.authorization_url.as_deref().unwrap_or("-"),
                                f.token_url.as_deref().unwrap_or("-"),
                                if f.scopes.is_empty() {
                                    "-".into()
                                } else {
                                    f.scopes.join(" ")
                                }
                            );
                        }
                    }
                    if let Scheme::OpenIdConnect { url } = &scheme {
                        let _ = write!(comment, "\n# OpenID Connect discovery: {url}");
                    }
                    let var = self.secret_var(scheme_name, "_TOKEN", comment);
                    if !scopes.is_empty() {
                        lines.push(format!("# Scopes: {}", scopes.join(" ")));
                    }
                    lines.push(format!(
                        "expand-header = {}",
                        quote(&format!("Authorization: Bearer {{{{{var}}}}}"))
                    ));
                }
            }
        }
    }

    /// Writes the body payload (if any) and returns curl lines for it.
    fn body_lines(&mut self, op: &Operation, body: &Body, stem: &Path) -> Result<Vec<String>> {
        let secrets = self.secrets.clone();
        let examples = Examples::new(self.spec, &secrets);
        let example = match (&body.example, &body.schema) {
            (Some(e), _) => examples.scrub(e.clone()),
            (None, Some(s)) => examples.example(s, Direction::Request),
            (None, None) => Value::Object(Default::default()),
        };
        let ct = body.content_type.as_str();
        let mut lines = Vec::new();
        if is_json_type(ct) {
            let rel = stem.with_extension("body.json");
            self.write(&rel, &(serde_json::to_string_pretty(&example)? + "\n"))?;
            if ct.starts_with("application/json") {
                lines.push(format!("json = @{}", rel.display()));
            } else {
                lines.push(format!(
                    "header = {}",
                    quote(&format!("Content-Type: {ct}"))
                ));
                lines.push(format!("data-binary = @{}", rel.display()));
            }
        } else if ct.starts_with("application/x-www-form-urlencoded")
            || ct.starts_with("multipart/form-data")
        {
            let option = if ct.starts_with("multipart") {
                "form-string"
            } else {
                "data-urlencode"
            };
            for (k, v) in example.as_object().into_iter().flatten() {
                lines.push(format!(
                    "{option} = {}",
                    quote(&format!("{k}={}", value_text(v)))
                ));
            }
        } else if ct.starts_with("text/") {
            lines.push(format!(
                "header = {}",
                quote(&format!("Content-Type: {ct}"))
            ));
            lines.push(format!("data-binary = {}", quote(&value_text(&example))));
        } else {
            lines.push(format!(
                "# Request body ({ct}): add data-binary = @path/to/file"
            ));
            lines.push(format!(
                "header = {}",
                quote(&format!("Content-Type: {ct}"))
            ));
            self.summary.warnings.push(format!(
                "{} {}: body type {ct} needs a file; left a comment in the request",
                op.method, op.path
            ));
        }
        if !op.body_required {
            lines.insert(0, "# Request body (optional)".into());
        }
        Ok(lines)
    }

    /// Generates the request, payload, sidecar, and schema for one operation.
    fn operation(&mut self, op: &Operation, folder: &Path, stem_name: &str) -> Result<()> {
        let stem = folder.join(stem_name);
        let mut text = String::new();
        let title = op
            .summary
            .clone()
            .or_else(|| op.operation_id.clone())
            .unwrap_or_else(|| format!("{} {}", op.method, op.path));
        let _ = writeln!(
            text,
            "# @name {}",
            title.lines().next().unwrap_or_default().trim()
        );
        if let Some(desc) = op
            .description
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            let mut lines = desc.lines();
            let _ = writeln!(
                text,
                "# @description {}",
                lines.next().unwrap_or_default().trim()
            );
            for l in lines {
                let l = l.trim_end();
                let _ = writeln!(
                    text,
                    "#   {}",
                    if l.trim_start().starts_with('@') {
                        format!("\\{}", l.trim_start())
                    } else {
                        l.to_string()
                    }
                );
            }
        }
        if !op.tags.is_empty() {
            let _ = writeln!(text, "# @tags {}", op.tags.join(", "));
        }
        if let Some(id) = &op.operation_id {
            let _ = writeln!(text, "# @operation {id}");
        }
        if op.deprecated {
            text.push_str("# @deprecated true\n");
        }
        let _ = writeln!(
            text,
            "# Generated by curly import from {}: {} {}",
            self.spec_file, op.method, op.path
        );

        let secrets = self.secrets.clone();
        let examples = Examples::new(self.spec, &secrets);
        let mut path = op.path.clone();
        let mut query = Vec::new();
        let mut headers = Vec::new();
        let mut cookies = Vec::new();
        let mut optional = BTreeMap::<&str, Vec<String>>::new();
        for p in &op.params {
            let var = var_name(&p.name);
            let example = p
                .example
                .clone()
                .unwrap_or_else(|| examples.example(&p.schema, Direction::Request));
            let secret = self.secrets.is_secret(&p.name);
            match p.location {
                ParamIn::Path => {
                    path = path.replace(&format!("{{{}}}", p.name), &format!("{{{{{var}:url}}}}"));
                }
                ParamIn::Query if p.required => query.push(format!("{}={{{{{var}:url}}}}", p.name)),
                ParamIn::Header if p.required => {
                    if !["accept", "content-type", "authorization"]
                        .contains(&p.name.to_ascii_lowercase().as_str())
                    {
                        headers.push(format!(
                            "expand-header = {}",
                            quote(&format!("{}: {{{{{var}}}}}", p.name))
                        ));
                    }
                }
                ParamIn::Cookie if p.required => cookies.push(format!("{}={{{{{var}}}}}", p.name)),
                ParamIn::Query => {
                    optional
                        .entry("query parameters")
                        .or_default()
                        .push(p.name.clone());
                    continue;
                }
                ParamIn::Header => {
                    optional.entry("headers").or_default().push(p.name.clone());
                    continue;
                }
                ParamIn::Cookie => {
                    optional.entry("cookies").or_default().push(p.name.clone());
                    continue;
                }
            }
            let comment = p
                .description
                .as_deref()
                .map(|d| format!("{} ({})", d.lines().next().unwrap_or_default(), p.name))
                .or_else(|| {
                    Some(format!(
                        "{} parameter `{}`",
                        format!("{:?}", p.location).to_lowercase(),
                        p.name
                    ))
                });
            if secret {
                self.secret_var(&p.name, "", comment.unwrap_or_default());
            } else {
                self.add_var(&var, Some(value_text(&example)), comment);
            }
        }
        let mut auth = Vec::new();
        self.auth_lines(op, &mut auth, &mut query, &mut cookies);
        let mut url = format!("{{{{BASE_URL}}}}{path}");
        if !query.is_empty() {
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&query.join("&"));
        }
        let _ = writeln!(text, "expand-url = {}", quote(&url));
        match op.method.as_str() {
            "GET" => {}
            "HEAD" => text.push_str("head\n"),
            m => {
                let _ = writeln!(text, "request = {}", quote(m));
            }
        }
        let success = op.responses.iter().find(|r| r.status.starts_with('2'));
        let accept = success.and_then(|r| {
            r.content_types
                .iter()
                .find(|c| is_json_type(c))
                .or(r.content_types.first())
                .cloned()
        });
        if let Some(a) = accept {
            let _ = writeln!(text, "header = {}", quote(&format!("Accept: {a}")));
        }
        for h in headers.iter().chain(auth.iter()) {
            let _ = writeln!(text, "{h}");
        }
        if !cookies.is_empty() {
            let _ = writeln!(text, "expand-cookie = {}", quote(&cookies.join("; ")));
        }
        if let Some(body) = &op.body {
            for l in self.body_lines(op, body, &stem)? {
                let _ = writeln!(text, "{l}");
            }
        }
        for (kind, names) in &optional {
            let _ = writeln!(text, "# Optional {kind}: {}", names.join(", "));
        }
        self.write(
            &stem.with_extension("curl"),
            &crate::curlconf::format_flags(&text),
        )?;

        let mut test = format!(
            "# Generated by curly import from {}. Edit freely: re-importing skips existing files.\n[expect]\n",
            self.spec_file
        );
        match success {
            Some(r) if r.status.len() == 3 && r.status.chars().all(|c| c.is_ascii_digit()) => {
                let _ = writeln!(test, "status = {}", r.status);
            }
            _ => test.push_str("status = \"2xx\"\n"),
        }
        if let Some(schema) = success
            .and_then(|r| r.body.as_ref())
            .filter(|b| is_json_type(&b.content_type))
            .and_then(|b| b.schema.as_ref())
        {
            let status = success
                .map(|r| r.status.to_ascii_lowercase())
                .unwrap_or_default();
            let schema_rel = folder.join(format!("{stem_name}.{status}.schema.json"));
            let doc = Converter::new(self.spec).document(schema);
            self.write(&schema_rel, &(serde_json::to_string_pretty(&doc)? + "\n"))?;
            let _ = writeln!(
                test,
                "schema = {}",
                quote(&schema_rel.display().to_string())
            );
        }
        self.write(
            &PathBuf::from(format!("{}{TEST_SUFFIX}", stem.display())),
            &test,
        )?;
        Ok(())
    }

    /// Appends missing variables to the environment file (creating it if needed).
    fn write_env(&mut self, env: &str) -> Result<()> {
        let specs: Vec<crate::vars::EnvVarSpec> = self
            .env_order
            .iter()
            .map(|name| {
                let v = &self.env_vars[name];
                crate::vars::EnvVarSpec {
                    name: name.clone(),
                    value: v.value.clone(),
                    comment: v.comment.clone(),
                }
            })
            .collect();
        let note = format!(
            "Added by `curly import` from {} ({})",
            self.spec_file, self.api.title
        );
        let (rel, added) = crate::vars::add_env_variables(&self.root, env, &specs, &note)?;
        self.summary.env_added.extend(added);
        self.summary.env_file = rel;
        Ok(())
    }
}

/// Imports `opts.source` and writes the generated collection files.
pub fn import(opts: &ImportOptions) -> Result<ImportSummary> {
    let text = fetch(&opts.source, &opts.curl, &opts.cwd)?;
    let spec = Spec::parse(&text)?;
    let api = normalize(&spec)?;
    if api.operations.is_empty() {
        bail!("the spec has no operations under `paths`");
    }
    let out = match &opts.out {
        Some(o) if o.is_absolute() => o.clone(),
        Some(o) => opts.cwd.join(o),
        None => opts.cwd.join(slug(&api.title)),
    };
    std::fs::create_dir_all(&out)?;
    let (project, new_collection) = match Project::discover(&out) {
        Ok(p) => (p, false),
        Err(_) => {
            project::init(
                &out,
                &InitOptions {
                    name: Some(&api.title),
                    env: &opts.env,
                    sample: false,
                },
            )?;
            (Project::load(&out)?, true)
        }
    };
    let out_rel = project.relative(&out)?;
    let spec_file = out_rel.join(format!(
        "openapi.{}",
        if spec.is_json { "json" } else { "yaml" }
    ));
    let mut g = Generator {
        spec: &spec,
        api: &api,
        secrets: SecretNames::new(&project.config.redact.variables)?,
        root: project.root.clone(),
        out_rel: out_rel.clone(),
        force: opts.force,
        spec_file: spec_file.display().to_string(),
        env_vars: BTreeMap::new(),
        env_order: Vec::new(),
        summary: ImportSummary {
            title: api.title.clone(),
            root: project.root.clone(),
            out: out_rel.clone(),
            new_collection,
            ..Default::default()
        },
    };
    g.add_var(
        "BASE_URL",
        Some(base_url(&api, &opts.source)),
        Some(format!("Base URL of {}", api.title)),
    );
    for (url, desc) in api.servers.iter().skip(1) {
        g.summary.warnings.push(format!(
            "other server: {url}{}",
            desc.as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        ));
    }
    g.write(&spec_file, &text)?;

    let mut folders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut used: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for op in &api.operations {
        let tag = op
            .tags
            .first()
            .map(|t| slug(t))
            .unwrap_or_else(|| "default".into());
        let base =
            op.operation_id.as_deref().map(slug).unwrap_or_else(|| {
                slug(&format!("{} {}", op.method.to_ascii_lowercase(), op.path))
            });
        let taken = used.entry(tag.clone()).or_default();
        let mut stem = base.clone();
        let mut n = 2;
        while !taken.insert(stem.clone()) {
            stem = format!("{base}-{n}");
            n += 1;
        }
        g.operation(op, &g.out_rel.join(&tag), &stem)?;
        folders.entry(tag).or_default().push(format!("{stem}.curl"));
    }
    let mut tag_order: Vec<String> = api
        .tags
        .iter()
        .map(|(t, _)| slug(t))
        .filter(|t| folders.contains_key(t))
        .collect();
    for op in &api.operations {
        let t = op
            .tags
            .first()
            .map(|t| slug(t))
            .unwrap_or_else(|| "default".into());
        if !tag_order.contains(&t) {
            tag_order.push(t);
        }
    }
    let root_cfg = format!(
        "# {} {}\n# Folders run in the order tags appear in {}.\norder = [{}]\n",
        api.title,
        api.version,
        g.spec_file,
        tag_order
            .iter()
            .map(|t| quote(&format!("{t}/")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    g.write(&out_rel.join(FOLDER_FILE), &root_cfg)?;
    for (tag, order) in &folders {
        let desc = api
            .tags
            .iter()
            .find(|(name, _)| slug(name) == *tag)
            .map(|(_, d)| d.clone())
            .unwrap_or_default();
        let mut cfg = String::new();
        for l in desc.lines().filter(|l| !l.trim().is_empty()) {
            let _ = writeln!(cfg, "# {}", l.trim());
        }
        let _ = writeln!(cfg, "# Run order follows {}.", g.spec_file);
        let _ = writeln!(
            cfg,
            "order = [{}]",
            order
                .iter()
                .map(|o| quote(o))
                .collect::<Vec<_>>()
                .join(", ")
        );
        g.write(&out_rel.join(tag).join(FOLDER_FILE), &cfg)?;
    }
    g.write_env(&opts.env)?;
    g.summary.operations = api.operations.len();
    Ok(g.summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_names() {
        assert_eq!(slug("getPetById"), "get-pet-by-id");
        assert_eq!(slug("get /pets/{petId}"), "get-pets-pet-id");
        assert_eq!(slug("Swagger Petstore v2"), "swagger-petstore-v2");
        assert_eq!(slug("--"), "api");
        assert_eq!(var_name("X-Request-ID"), "X_Request_ID");
        assert_eq!(upper_snake("bearerAuth"), "BEARER_AUTH");
        assert_eq!(upper_snake("petstore_auth"), "PETSTORE_AUTH");
    }

    #[test]
    fn base_urls() {
        let api = |url: &str| Api {
            title: String::new(),
            version: String::new(),
            description: None,
            servers: vec![(url.into(), None)],
            tags: vec![],
            operations: vec![],
            schemes: BTreeMap::new(),
            security: vec![],
        };
        assert_eq!(
            base_url(&api("https://api.example.com/v1/"), "spec.yaml"),
            "https://api.example.com/v1"
        );
        assert_eq!(
            base_url(&api("/api"), "http://127.0.0.1:9/openapi.yaml"),
            "http://127.0.0.1:9/api"
        );
        assert_eq!(base_url(&api("/api"), "spec.yaml"), "http://localhost/api");
    }
}
