//! OAuth 2.0 for `_folder.toml` `[auth]`: authorization code with PKCE (system
//! browser + loopback redirect), client credentials, and refresh tokens.
//!
//! Tokens are cached in the secret store (OS keychain by default) and refreshed
//! automatically; the access token reaches requests as a secret curl variable
//! (`token_var`, default `ACCESS_TOKEN`). Token requests go through the system
//! curl like every other request, and secret form values reach curl through the
//! child environment, never argv or files.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::curlconf::{quote, substitute};
use crate::curlexec::{Curl, Exchange, Invocation};
use crate::folder;
use crate::history::NewEntry;
use crate::project::Project;
use crate::redact::Redactor;
use crate::request::{open_history, sha256_hex};
use crate::secrets::open_store;
use crate::vars::{ConfigLayer, SecretNames, VarContext};

/// Refresh tokens this many seconds before they expire.
const EXPIRY_MARGIN_SECS: i64 = 30;

/// `[auth] type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// OAuth 2.0.
    Oauth2,
    /// No auth; stops inheritance from parent folders.
    None,
}

/// `[auth] flow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    /// Browser login with PKCE.
    AuthorizationCode,
    /// Machine-to-machine with a client secret.
    ClientCredentials,
    /// Exchange a long-lived refresh token from a variable.
    RefreshToken,
}

impl Flow {
    /// Config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Flow::AuthorizationCode => "authorization_code",
            Flow::ClientCredentials => "client_credentials",
            Flow::RefreshToken => "refresh_token",
        }
    }
}

/// How the client authenticates to the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// HTTP Basic (`client_secret_basic`, RFC 6749 §2.3.1).
    #[default]
    Basic,
    /// Form fields (`client_secret_post`).
    Body,
}

fn default_true() -> bool {
    true
}

fn default_redirect_path() -> String {
    "/callback".into()
}

fn default_token_var() -> String {
    "ACCESS_TOKEN".into()
}

/// `[auth]` table in `_folder.toml`. String fields may use `{{variables}}`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// `oauth2` or `none`.
    #[serde(rename = "type")]
    pub kind: AuthKind,
    /// Grant flow.
    pub flow: Option<Flow>,
    /// Authorization endpoint (authorization code flow).
    pub auth_url: Option<String>,
    /// Token endpoint.
    pub token_url: Option<String>,
    /// Client id.
    pub client_id: Option<String>,
    /// Client secret; must be a `{{variable}}` reference.
    pub client_secret: Option<String>,
    /// Refresh token for the `refresh_token` flow; must be a `{{variable}}` reference.
    pub refresh_token: Option<String>,
    /// Requested scopes.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Use PKCE (S256) in the authorization code flow.
    #[serde(default = "default_true")]
    pub pkce: bool,
    /// Loopback port for the redirect (0 = any free port).
    #[serde(default)]
    pub redirect_port: u16,
    /// Path of the redirect URI.
    #[serde(default = "default_redirect_path")]
    pub redirect_path: String,
    /// Client authentication method at the token endpoint.
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// Extra parameters sent to the authorize and token endpoints (e.g. `audience`).
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    /// Variable that receives the access token.
    #[serde(default = "default_token_var")]
    pub token_var: String,
}

impl AuthConfig {
    /// Configuration problems (empty when valid).
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.kind == AuthKind::None {
            return out;
        }
        let Some(flow) = self.flow else {
            return vec!["[auth] type = \"oauth2\" needs flow = \"authorization_code\", \"client_credentials\", or \"refresh_token\"".into()];
        };
        let mut need = |field: &str, v: &Option<String>| {
            if v.as_deref().is_none_or(str::is_empty) {
                out.push(format!("[auth] flow `{}` needs `{field}`", flow.as_str()));
            }
        };
        need("token_url", &self.token_url);
        need("client_id", &self.client_id);
        match flow {
            Flow::AuthorizationCode => need("auth_url", &self.auth_url),
            Flow::ClientCredentials => need("client_secret", &self.client_secret),
            Flow::RefreshToken => need("refresh_token", &self.refresh_token),
        }
        for (field, v) in [
            ("client_secret", &self.client_secret),
            ("refresh_token", &self.refresh_token),
        ] {
            if v.as_deref().is_some_and(|s| !s.contains("{{")) {
                out.push(format!("hardcoded credential in [auth] {field}; use a {{{{variable}}}} from an environment secret"));
            }
        }
        if !self.redirect_path.starts_with('/') {
            out.push("[auth] redirect_path must start with `/`".into());
        }
        if self.token_var.is_empty()
            || !self
                .token_var
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            out.push(format!(
                "[auth] token_var `{}` is not a valid variable name",
                self.token_var
            ));
        }
        out
    }

    /// Copy with `{{variables}}` substituted in every string field.
    fn substituted(&self, vars: &BTreeMap<String, String>) -> Result<AuthConfig> {
        let sub = |v: &Option<String>, field: &str| -> Result<Option<String>> {
            v.as_deref()
                .map(|s| substitute(s, vars).map_err(|e| anyhow::anyhow!("[auth] {field}: {e}")))
                .transpose()
        };
        let mut c = self.clone();
        c.auth_url = sub(&self.auth_url, "auth_url")?;
        c.token_url = sub(&self.token_url, "token_url")?;
        c.client_id = sub(&self.client_id, "client_id")?;
        c.client_secret = sub(&self.client_secret, "client_secret")?;
        c.refresh_token = sub(&self.refresh_token, "refresh_token")?;
        c.scopes = self
            .scopes
            .iter()
            .map(|s| substitute(s, vars).map_err(|e| anyhow::anyhow!("[auth] scopes: {e}")))
            .collect::<Result<_>>()?;
        c.params = self
            .params
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    substitute(v, vars).map_err(|e| anyhow::anyhow!("[auth] params.{k}: {e}"))?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(c)
    }
}

/// Path used to look up the folder chain: folders get a virtual child entry.
pub fn chain_anchor(project: &Project, rel: &Path) -> PathBuf {
    if project.root.join(rel).is_dir() {
        rel.join("_")
    } else {
        rel.to_path_buf()
    }
}

/// The nearest `[auth]` for `rel` (file or folder) and the folder that declares it.
/// Returns `None` when there is none or the nearest one is `type = "none"`.
pub fn find(project: &Project, rel: &Path) -> Result<Option<(PathBuf, AuthConfig)>> {
    let anchor = chain_anchor(project, rel);
    let chain = folder::chain(project, &anchor)?;
    for (path, cfg) in chain.into_iter().rev() {
        if let Some(auth) = cfg.auth {
            let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
            return Ok((auth.kind == AuthKind::Oauth2).then_some((dir, auth)));
        }
    }
    Ok(None)
}

/// An `[auth]` with variables substituted, ready to use.
#[derive(Debug, Clone)]
pub struct ResolvedAuth {
    /// Folder that declares it (collection-relative; empty = root).
    pub folder: PathBuf,
    /// Environment name used for caching.
    pub env: String,
    /// Substituted config.
    pub cfg: AuthConfig,
}

impl ResolvedAuth {
    /// Flow (validated to be present).
    pub fn flow(&self) -> Flow {
        self.cfg.flow.unwrap_or(Flow::ClientCredentials)
    }

    /// Stable cache key for this environment, endpoint, client, flow, and scopes.
    pub fn cache_key(&self) -> String {
        let mut scopes = self.cfg.scopes.clone();
        scopes.sort();
        let material = serde_json::json!([
            self.env,
            self.cfg.token_url,
            self.cfg.client_id,
            self.flow().as_str(),
            scopes,
            self.cfg.params
        ]);
        sha256_hex(material.to_string().as_bytes())[..16].to_string()
    }

    /// Folder for messages and commands (`.` for the root).
    pub fn folder_display(&self) -> String {
        if self.folder.as_os_str().is_empty() {
            ".".into()
        } else {
            self.folder.display().to_string()
        }
    }
}

/// Finds and substitutes the `[auth]` for `rel` using the variables in `ctx`.
pub fn resolve(project: &Project, rel: &Path, ctx: &VarContext) -> Result<Option<ResolvedAuth>> {
    let Some((folder, cfg)) = find(project, rel)? else {
        return Ok(None);
    };
    let problems = cfg.problems();
    if !problems.is_empty() {
        bail!(
            "{}: {}",
            folder.join(folder::FOLDER_FILE).display(),
            problems.join("; ")
        );
    }
    let cfg = cfg.substituted(&ctx.values(&project.root))?;
    let env = ctx
        .env
        .as_ref()
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "default".into());
    Ok(Some(ResolvedAuth { folder, env, cfg }))
}

/// A cached token set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenSet {
    /// Access token.
    pub access_token: String,
    /// Token type (usually `Bearer`).
    pub token_type: String,
    /// Refresh token, if issued.
    pub refresh_token: Option<String>,
    /// Expiry as Unix seconds, if known.
    pub expires_at: Option<i64>,
    /// Granted scopes.
    pub scope: Option<String>,
}

impl TokenSet {
    /// True if the token is usable for at least the expiry margin.
    pub fn is_fresh(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|t| t - EXPIRY_MARGIN_SECS > now)
    }
}

/// Non-secret description of a cached token, kept in `.curly/oauth.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    /// Environment.
    pub env: String,
    /// Folder declaring `[auth]`.
    pub folder: String,
    /// Flow.
    pub flow: String,
    /// Client id.
    pub client_id: String,
    /// Token endpoint.
    pub token_url: String,
    /// Scopes requested.
    pub scopes: Vec<String>,
    /// Expiry (Unix seconds).
    pub expires_at: Option<i64>,
    /// Whether a refresh token is cached.
    pub refreshable: bool,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn index_path(project: &Project) -> Result<PathBuf> {
    Ok(project.state_dir()?.join("oauth.json"))
}

/// Reads the cache index.
pub fn cache_index(project: &Project) -> Result<BTreeMap<String, CacheMeta>> {
    match std::fs::read_to_string(index_path(project)?) {
        Ok(s) => Ok(serde_json::from_str(&s).context("parsing .curly/oauth.json")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}

fn write_index(project: &Project, index: &BTreeMap<String, CacheMeta>) -> Result<()> {
    std::fs::write(index_path(project)?, serde_json::to_string_pretty(index)?)?;
    Ok(())
}

fn store_name(key: &str) -> String {
    format!("oauth:{key}")
}

fn load_cached(project: &Project, auth: &ResolvedAuth) -> Result<Option<TokenSet>> {
    let store = open_store(project)?;
    Ok(store
        .get(&auth.env, &store_name(&auth.cache_key()))?
        .and_then(|s| serde_json::from_str(&s).ok()))
}

fn save_cached(project: &Project, auth: &ResolvedAuth, tokens: &TokenSet) -> Result<()> {
    let key = auth.cache_key();
    open_store(project)?.set(
        &auth.env,
        &store_name(&key),
        &serde_json::to_string(tokens)?,
    )?;
    let mut index = cache_index(project)?;
    index.insert(
        key,
        CacheMeta {
            env: auth.env.clone(),
            folder: auth.folder_display(),
            flow: auth.flow().as_str().into(),
            client_id: auth.cfg.client_id.clone().unwrap_or_default(),
            token_url: auth.cfg.token_url.clone().unwrap_or_default(),
            scopes: auth.cfg.scopes.clone(),
            expires_at: tokens.expires_at,
            refreshable: tokens.refresh_token.is_some(),
        },
    );
    write_index(project, &index)
}

/// Deletes cached tokens matching `filter`; returns how many were removed.
pub fn logout(project: &Project, filter: &dyn Fn(&CacheMeta) -> bool) -> Result<usize> {
    let store = open_store(project)?;
    let mut index = cache_index(project)?;
    let doomed: Vec<String> = index
        .iter()
        .filter(|(_, m)| filter(m))
        .map(|(k, _)| k.clone())
        .collect();
    for key in &doomed {
        if let Some(meta) = index.remove(key) {
            store.delete(&meta.env, &store_name(key))?;
        }
    }
    write_index(project, &index)?;
    Ok(doomed.len())
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
pub fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Decodes `%XX` and `+` in a query component.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'%' && i + 2 < bytes.len())
            .then(|| {
                std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            })
            .flatten();
        match (bytes[i], hex) {
            (_, Some(v)) => {
                out.push(v);
                i += 3;
                continue;
            }
            (b'+', None) => out.push(b' '),
            (b, None) => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `a=1&b=2` into pairs.
fn parse_query(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

/// `n` random bytes as base64url without padding.
fn random_b64(n: usize) -> String {
    let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A PKCE verifier (43 chars from 32 random bytes) and its S256 challenge (RFC 7636).
pub fn pkce_pair() -> (String, String) {
    let verifier = random_b64(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Constant-time string comparison.
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// One token endpoint parameter.
struct Param {
    name: String,
    value: String,
    secret: bool,
}

impl Param {
    fn new(name: &str, value: impl Into<String>, secret: bool) -> Param {
        Param {
            name: name.into(),
            value: value.into(),
            secret,
        }
    }
}

/// Sends a token request with curl and parses the response.
fn token_request(
    project: &Project,
    curl: &Curl,
    auth: &ResolvedAuth,
    mut params: Vec<Param>,
) -> Result<TokenSet> {
    let cfg = &auth.cfg;
    let names = SecretNames::new(&project.config.redact.variables)?;
    for (k, v) in &cfg.params {
        params.push(Param::new(k, v.clone(), names.is_secret(k)));
    }
    if !cfg.scopes.is_empty() && !params.iter().any(|p| p.name == "scope") {
        params.push(Param::new("scope", cfg.scopes.join(" "), false));
    }
    let client_id = cfg.client_id.clone().unwrap_or_default();
    let mut text = format!(
        "# generated by curly: OAuth token request\nurl = {}\nheader = \"Accept: application/json\"\n",
        quote(cfg.token_url.as_deref().unwrap_or_default())
    );
    let mut child_env = Vec::new();
    let mut secrets = Vec::new();
    match (&cfg.client_secret, cfg.client_auth) {
        (Some(secret), ClientAuth::Basic) => {
            child_env.push(("CURLY_OAUTH_CLIENT_ID".to_string(), client_id.clone()));
            child_env.push(("CURLY_OAUTH_CLIENT_SECRET".to_string(), secret.clone()));
            secrets.push(("client_secret".to_string(), secret.clone()));
            text.push_str("variable = %CURLY_OAUTH_CLIENT_ID\nvariable = %CURLY_OAUTH_CLIENT_SECRET\nexpand-user = \"{{CURLY_OAUTH_CLIENT_ID}}:{{CURLY_OAUTH_CLIENT_SECRET}}\"\n");
        }
        (Some(secret), ClientAuth::Body) => {
            params.push(Param::new("client_id", client_id.clone(), false));
            params.push(Param::new("client_secret", secret.clone(), true));
        }
        (None, _) => params.push(Param::new("client_id", client_id.clone(), false)),
    }
    for (i, p) in params.iter().enumerate() {
        if p.secret {
            let var = format!("CURLY_OAUTH_P{i}");
            child_env.push((var.clone(), p.value.clone()));
            secrets.push((p.name.clone(), p.value.clone()));
            text.push_str(&format!(
                "variable = %{var}\nexpand-data-urlencode = {}\n",
                quote(&format!("{}={{{{{var}}}}}", p.name))
            ));
        } else {
            text.push_str(&format!(
                "data-urlencode = {}\n",
                quote(&format!("{}={}", p.name, p.value))
            ));
        }
    }
    let inv = Invocation {
        root: project.root.clone(),
        layers: vec![],
        request: ConfigLayer::Text(text),
        child_env,
    };
    let raw = inv.execute(curl)?;
    let redactor = Redactor::new(&project.config.redact, secrets)?;
    let shown = redactor.exchange(&raw);
    record_history(project, auth, &shown, &raw)?;
    parse_token_response(&raw, &redactor)
}

/// Records a token request in history (always redacted).
fn record_history(
    project: &Project,
    auth: &ResolvedAuth,
    shown: &Exchange,
    raw: &Exchange,
) -> Result<()> {
    if !project.config.history.enabled {
        return Ok(());
    }
    let stored = if project.config.redact.enabled {
        shown
    } else {
        raw
    };
    let meta = NewEntry {
        file: None,
        env: Some(auth.env.clone()),
        vars: BTreeMap::new(),
        file_sha256: None,
        redacted: project.config.redact.enabled,
    };
    open_history(project)?.insert(&meta, stored, project.config.history.max_body_bytes)?;
    Ok(())
}

/// Parses a token endpoint response (RFC 6749 §5.1 / §5.2).
fn parse_token_response(raw: &Exchange, redactor: &Redactor) -> Result<TokenSet> {
    let Some(resp) = &raw.response else {
        bail!(
            "token request failed: {}",
            redactor.scrub(raw.error.as_deref().unwrap_or("no response"))
        );
    };
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    if !(200..300).contains(&resp.status) {
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("error");
        let desc = body
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        bail!(
            "token endpoint returned {}: {}",
            resp.status,
            redactor.scrub(format!("{err} {desc}").trim())
        );
    }
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .context("token response has no access_token")?
        .to_string();
    Ok(TokenSet {
        access_token,
        token_type: body
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer")
            .to_string(),
        refresh_token: body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        expires_at: body
            .get("expires_in")
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .map(|s| now() + s),
        scope: body
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// Opens `url` in the system browser, or with `CURLY_BROWSER` (a command line).
fn open_browser(url: &str) -> Result<Child> {
    let mut cmd = if let Ok(custom) = std::env::var("CURLY_BROWSER") {
        let mut parts = custom.split_whitespace();
        let mut c = Command::new(parts.next().context("CURLY_BROWSER is empty")?);
        c.args(parts);
        c
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("cannot open a browser (set CURLY_BROWSER or use --no-browser)")
}

fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!DOCTYPE html><html><head><title>curly</title></head><body><h1>curly</h1><p>{message}</p></body></html>"
    );
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Waits for the redirect on `listener` and returns the authorization code.
/// Gives up early if the `browser` command exits with a failure.
fn wait_for_code(
    listener: &TcpListener,
    path: &str,
    state: &str,
    timeout: Duration,
    mut browser: Option<&mut Child>,
) -> Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    bail!(
                        "timed out after {} s waiting for the browser redirect",
                        timeout.as_secs()
                    );
                }
                if let Some(child) = browser.as_deref_mut()
                    && let Some(status) = child.try_wait()?
                {
                    if !status.success() {
                        bail!("the browser command exited with {status} before the login finished");
                    }
                    browser = None;
                }
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let target = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        let (req_path, query) = target.split_once('?').unwrap_or((&target, ""));
        if req_path != path {
            respond(&mut stream, "404 Not Found", "Not found.");
            continue;
        }
        let q = parse_query(query);
        if let Some(err) = q.get("error") {
            respond(
                &mut stream,
                "400 Bad Request",
                "Login failed. You can close this tab.",
            );
            bail!(
                "authorization failed: {err} {}",
                q.get("error_description").cloned().unwrap_or_default()
            );
        }
        if !ct_eq(
            q.get("state").map(String::as_str).unwrap_or_default(),
            state,
        ) {
            respond(
                &mut stream,
                "400 Bad Request",
                "State mismatch. You can close this tab.",
            );
            bail!(
                "redirect `state` did not match; the login was not started by this curly process"
            );
        }
        let Some(code) = q.get("code").filter(|c| !c.is_empty()) else {
            respond(&mut stream, "400 Bad Request", "No code in redirect.");
            bail!("redirect had no `code`");
        };
        respond(
            &mut stream,
            "200 OK",
            "Login complete. You can close this tab and return to the terminal.",
        );
        return Ok(code.clone());
    }
}

/// Options for interactive login.
#[derive(Debug, Clone)]
pub struct LoginOptions {
    /// Open the browser automatically (otherwise only print the URL).
    pub open_browser: bool,
    /// How long to wait for the redirect.
    pub timeout: Duration,
}

impl Default for LoginOptions {
    fn default() -> Self {
        LoginOptions {
            open_browser: true,
            timeout: Duration::from_secs(300),
        }
    }
}

/// Runs the authorization code flow (with PKCE) and exchanges the code.
fn authorization_code(
    project: &Project,
    curl: &Curl,
    auth: &ResolvedAuth,
    opts: &LoginOptions,
) -> Result<TokenSet> {
    let cfg = &auth.cfg;
    let listener = TcpListener::bind(("127.0.0.1", cfg.redirect_port))
        .context("binding the loopback redirect listener")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{}",
        listener.local_addr()?.port(),
        cfg.redirect_path
    );
    let state = random_b64(16);
    let pkce = cfg.pkce.then(pkce_pair);
    let mut query = vec![
        ("response_type".to_string(), "code".to_string()),
        (
            "client_id".into(),
            cfg.client_id.clone().unwrap_or_default(),
        ),
        ("redirect_uri".into(), redirect_uri.clone()),
        ("state".into(), state.clone()),
    ];
    if !cfg.scopes.is_empty() {
        query.push(("scope".into(), cfg.scopes.join(" ")));
    }
    if let Some((_, challenge)) = &pkce {
        query.push(("code_challenge".into(), challenge.clone()));
        query.push(("code_challenge_method".into(), "S256".into()));
    }
    query.extend(cfg.params.iter().map(|(k, v)| (k.clone(), v.clone())));
    let auth_url = cfg.auth_url.clone().unwrap_or_default();
    let sep = if auth_url.contains('?') { '&' } else { '?' };
    let url = format!(
        "{auth_url}{sep}{}",
        query
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    );
    eprintln!(
        "Log in for {} in your browser. If it does not open, visit:\n  {url}",
        auth.folder_display()
    );
    let mut child = if opts.open_browser {
        Some(open_browser(&url)?)
    } else {
        None
    };
    let code = wait_for_code(
        &listener,
        &cfg.redirect_path,
        &state,
        opts.timeout,
        child.as_mut(),
    );
    if let Some(c) = child.as_mut() {
        let _ = c.wait();
    }
    let code = code?;
    let mut params = vec![
        Param::new("grant_type", "authorization_code", false),
        Param::new("code", code, true),
        Param::new("redirect_uri", redirect_uri, false),
    ];
    if let Some((verifier, _)) = pkce {
        params.push(Param::new("code_verifier", verifier, true));
    }
    token_request(project, curl, auth, params)
}

/// Gets fresh tokens for `auth` without using the cache, then caches them.
pub fn login(
    project: &Project,
    curl: &Curl,
    auth: &ResolvedAuth,
    opts: &LoginOptions,
) -> Result<TokenSet> {
    let tokens = match auth.flow() {
        Flow::AuthorizationCode => authorization_code(project, curl, auth, opts)?,
        Flow::ClientCredentials => token_request(
            project,
            curl,
            auth,
            vec![Param::new("grant_type", "client_credentials", false)],
        )?,
        Flow::RefreshToken => refresh(
            project,
            curl,
            auth,
            auth.cfg.refresh_token.clone().unwrap_or_default(),
        )?,
    };
    save_cached(project, auth, &tokens)?;
    Ok(tokens)
}

fn refresh(
    project: &Project,
    curl: &Curl,
    auth: &ResolvedAuth,
    refresh_token: String,
) -> Result<TokenSet> {
    let mut t = token_request(
        project,
        curl,
        auth,
        vec![
            Param::new("grant_type", "refresh_token", false),
            Param::new("refresh_token", refresh_token.clone(), true),
        ],
    )?;
    if t.refresh_token.is_none() {
        t.refresh_token = Some(refresh_token);
    }
    Ok(t)
}

/// Whether a browser login may start automatically (interactive terminal).
pub fn interactive() -> bool {
    std::io::stderr().is_terminal()
        && std::io::stdin().is_terminal()
        && std::env::var_os("CURLY_NO_BROWSER").is_none()
        && std::env::var_os("CI").is_none()
}

/// Returns a valid access token: cached, refreshed, or newly fetched.
/// Browser logins only start when `allow_login` is set.
pub fn access_token(
    project: &Project,
    curl: &Curl,
    auth: &ResolvedAuth,
    allow_login: bool,
) -> Result<String> {
    if let Some(cached) = load_cached(project, auth)? {
        if cached.is_fresh(now()) {
            return Ok(cached.access_token);
        }
        if let Some(rt) = cached.refresh_token.clone()
            && let Ok(t) = refresh(project, curl, auth, rt)
        {
            save_cached(project, auth, &t)?;
            return Ok(t.access_token);
        }
    }
    match auth.flow() {
        Flow::AuthorizationCode if !allow_login => {
            bail!(
                "no valid OAuth token for {}; run `curly auth login {} -e {}`",
                auth.folder_display(),
                auth.folder_display(),
                auth.env
            )
        }
        _ => Ok(login(project, curl, auth, &LoginOptions::default())?.access_token),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml_text: &str) -> AuthConfig {
        toml::from_str(toml_text).unwrap()
    }

    #[test]
    fn validates_configs() {
        let ok = cfg(
            "type = \"oauth2\"\nflow = \"client_credentials\"\ntoken_url = \"https://x/token\"\nclient_id = \"id\"\nclient_secret = \"{{SECRET}}\"\n",
        );
        assert!(ok.problems().is_empty(), "{:?}", ok.problems());
        assert_eq!(ok.token_var, "ACCESS_TOKEN");
        assert!(ok.pkce);
        let literal = cfg(
            "type = \"oauth2\"\nflow = \"client_credentials\"\ntoken_url = \"t\"\nclient_id = \"id\"\nclient_secret = \"plain\"\n",
        );
        assert!(
            literal
                .problems()
                .iter()
                .any(|p| p.contains("hardcoded credential in [auth] client_secret"))
        );
        let missing = cfg(
            "type = \"oauth2\"\nflow = \"authorization_code\"\ntoken_url = \"t\"\nclient_id = \"id\"\n",
        );
        assert_eq!(
            missing.problems(),
            vec!["[auth] flow `authorization_code` needs `auth_url`"]
        );
        assert!(cfg("type = \"oauth2\"\n").problems()[0].contains("needs flow"));
        assert!(cfg("type = \"none\"\n").problems().is_empty());
        assert!(toml::from_str::<AuthConfig>("type = \"oauth2\"\nflw = \"x\"\n").is_err());
    }

    #[test]
    fn substitutes_variables() {
        let c = cfg(
            "type = \"oauth2\"\nflow = \"client_credentials\"\ntoken_url = \"{{BASE}}/token\"\nclient_id = \"{{ID}}\"\nclient_secret = \"{{S}}\"\nscopes = [\"{{SCOPE}}\"]\n[params]\naudience = \"{{BASE}}\"\n",
        );
        let vars = BTreeMap::from(
            [
                ("BASE", "https://a"),
                ("ID", "me"),
                ("S", "sek"),
                ("SCOPE", "read"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        let s = c.substituted(&vars).unwrap();
        assert_eq!(s.token_url.as_deref(), Some("https://a/token"));
        assert_eq!(s.client_secret.as_deref(), Some("sek"));
        assert_eq!(s.scopes, vec!["read"]);
        assert_eq!(s.params["audience"], "https://a");
        assert!(
            c.substituted(&BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("[auth] token_url")
        );
    }

    #[test]
    fn pkce_and_encoding() {
        let (v, c) = pkce_pair();
        assert_eq!(v.len(), 43);
        assert_eq!(c, URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())));
        assert_ne!(pkce_pair().0, v, "verifiers are random");
        let rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(rfc_verifier.as_bytes())),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "RFC 7636 appendix B"
        );
        assert_eq!(percent_encode("a b/c~"), "a%20b%2Fc~");
        assert_eq!(percent_decode("a%20b+c%2F%zz"), "a b c/%zz");
        assert_eq!(parse_query("code=x%2By&state=s")["code"], "x+y");
        assert!(ct_eq("abc", "abc") && !ct_eq("abc", "abd") && !ct_eq("abc", "ab"));
    }

    #[test]
    fn freshness() {
        let t = TokenSet {
            access_token: "a".into(),
            token_type: "Bearer".into(),
            refresh_token: None,
            expires_at: Some(1000),
            scope: None,
        };
        assert!(t.is_fresh(900));
        assert!(!t.is_fresh(980), "inside the expiry margin");
        assert!(
            TokenSet {
                expires_at: None,
                ..t
            }
            .is_fresh(i64::MAX)
        );
    }

    #[test]
    fn callback_listener_checks_state() {
        let listener = std::sync::Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
        let port = listener.local_addr().unwrap().port();
        let send = move |target: &str| {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(s, "GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        };
        let wait = |l: std::sync::Arc<TcpListener>| {
            std::thread::spawn(move || {
                wait_for_code(&l, "/callback", "s1", Duration::from_secs(5), None)
            })
        };
        let waiter = wait(listener.clone());
        assert!(
            send("/favicon.ico").starts_with("HTTP/1.1 404"),
            "other paths get 404 and the wait continues"
        );
        assert!(send("/callback?code=abc&state=s1").contains("Login complete"));
        assert_eq!(waiter.join().unwrap().unwrap(), "abc");
        let waiter = wait(listener.clone());
        assert!(send("/callback?code=abc&state=evil").starts_with("HTTP/1.1 400"));
        let err = waiter.join().unwrap().unwrap_err();
        assert!(err.to_string().contains("state"), "{err}");
        let err = wait_for_code(
            &listener,
            "/callback",
            "s1",
            Duration::from_millis(100),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }
}
