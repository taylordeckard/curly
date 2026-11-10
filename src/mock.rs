//! `curly mock`: a local mock server built from an OpenAPI/Swagger spec and/or
//! saved example responses (`<request>.example.json`). It binds to loopback
//! addresses only.
//!
//! Example files sit next to request files: `get-user.example.json` is the
//! default response for that request's route, and `get-user.404.example.json`
//! is selected with `Prefer: code=404` (or `?__code=404`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::curlconf::RequestSpec;
use crate::openapi::model::{Spec, normalize};
use crate::openapi::schema::{Converter, Direction, Examples};
use crate::project::Project;
use crate::vars::SecretNames;

/// One path segment of a route template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Must match exactly.
    Literal(String),
    /// Matches any single segment.
    Param(String),
}

/// A canned response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Canned {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// JSON body, or a string for non-JSON bodies.
    #[serde(default)]
    pub body: Value,
}

impl Canned {
    fn body_bytes(&self) -> Vec<u8> {
        match &self.body {
            Value::Null => vec![],
            Value::String(s) if !self.is_json() => s.clone().into_bytes(),
            other => serde_json::to_vec_pretty(other).unwrap_or_default(),
        }
    }

    fn is_json(&self) -> bool {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .is_none_or(|(_, v)| v.contains("json"))
    }
}

/// A mocked route.
#[derive(Debug, Clone)]
pub struct Route {
    /// Upper-case method.
    pub method: String,
    /// Path template.
    pub segments: Vec<Segment>,
    /// Label for logs (operation id or request file).
    pub label: String,
    /// Where it came from (`openapi` or `examples`).
    pub source: &'static str,
    /// Responses; the first is the default.
    pub responses: Vec<Canned>,
    /// JSON Schema for the request body (used with `--validate`).
    pub body_schema: Option<Value>,
    /// Required query parameters (used with `--validate`).
    pub required_query: Vec<String>,
}

impl Route {
    /// `/users/{id}` form of the template.
    pub fn path(&self) -> String {
        let parts: Vec<String> = self
            .segments
            .iter()
            .map(|s| match s {
                Segment::Literal(l) => l.clone(),
                Segment::Param(p) => format!("{{{p}}}"),
            })
            .collect();
        format!("/{}", parts.join("/"))
    }

    fn literal_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| matches!(s, Segment::Literal(_)))
            .count()
    }
}

/// Parses an OpenAPI path template (`/users/{id}`).
pub fn parse_template(path: &str) -> Vec<Segment> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.contains('{') {
                Segment::Param(s.trim_matches(|c| c == '{' || c == '}').to_string())
            } else {
                Segment::Literal(s.to_string())
            }
        })
        .collect()
}

/// Path template of a request file's URL: drops a leading `{{VAR}}` or
/// `scheme://host`, the query string, and turns `{{var}}` segments into params.
pub fn template_from_url(url: &str) -> Vec<Segment> {
    let mut rest = url;
    if rest.starts_with("{{") {
        rest = rest.find("}}").map(|i| &rest[i + 2..]).unwrap_or("");
    } else if let Some((_, after)) = rest.split_once("://") {
        rest = after.find('/').map(|i| &after[i..]).unwrap_or("/");
    }
    let path = rest.split(['?', '#']).next().unwrap_or("");
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| match crate::curlconf::var_refs(s).first() {
            Some(name) => Segment::Param(name.clone()),
            None => Segment::Literal(s.to_string()),
        })
        .collect()
}

/// Builds routes from an OpenAPI/Swagger document.
pub fn routes_from_spec(text: &str) -> Result<Vec<Route>> {
    let spec = Spec::parse(text)?;
    let api = normalize(&spec)?;
    let names = SecretNames::new(&[])?;
    let examples = Examples::new(&spec, &names);
    let base: Vec<Segment> = api
        .servers
        .first()
        .map(|(u, _)| template_from_url(u))
        .unwrap_or_default();
    let mut routes = Vec::new();
    for op in &api.operations {
        let mut responses: Vec<(u16, Canned)> = Vec::new();
        for r in &op.responses {
            let status = match r.status.to_ascii_uppercase().as_str() {
                s if s.len() == 3 && s.ends_with("XX") => {
                    s[..1].parse::<u16>().map(|c| c * 100).unwrap_or(200)
                }
                "DEFAULT" => 500,
                s => s.parse().unwrap_or(200),
            };
            let mut headers = BTreeMap::new();
            let body = match &r.body {
                Some(b) => {
                    headers.insert("content-type".to_string(), b.content_type.clone());
                    let v = match (&b.example, &b.schema) {
                        (Some(e), _) => e.clone(),
                        (None, Some(s)) => examples.example(s, Direction::Response),
                        (None, None) => Value::Null,
                    };
                    if b.content_type.contains("json") {
                        v
                    } else {
                        Value::String(match v {
                            Value::String(s) => s,
                            other => other.to_string(),
                        })
                    }
                }
                None => Value::Null,
            };
            responses.push((
                status,
                Canned {
                    status,
                    headers,
                    body,
                },
            ));
        }
        responses.sort_by_key(|(s, _)| (!(200..300).contains(s), *s));
        if responses.is_empty() {
            responses.push((
                200,
                Canned {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: Value::Null,
                },
            ));
        }
        let body_schema = op
            .body
            .as_ref()
            .and_then(|b| b.schema.as_ref())
            .filter(|_| {
                op.body
                    .as_ref()
                    .is_some_and(|b| b.content_type.contains("json"))
            })
            .map(|s| Converter::new(&spec).document(s));
        let mut segments = base.clone();
        segments.extend(parse_template(&op.path));
        routes.push(Route {
            method: op.method.clone(),
            segments,
            label: op
                .operation_id
                .clone()
                .unwrap_or_else(|| format!("{} {}", op.method, op.path)),
            source: "openapi",
            responses: responses.into_iter().map(|(_, c)| c).collect(),
            body_schema: if op.body_required { body_schema } else { None },
            required_query: op
                .params
                .iter()
                .filter(|p| p.required && p.location == crate::openapi::model::ParamIn::Query)
                .map(|p| p.name.clone())
                .collect(),
        });
    }
    Ok(routes)
}

/// `get-user.curl` -> `get-user.example.json` (default) or `get-user.404.example.json`.
pub fn example_path(request: &Path, status: Option<u16>) -> PathBuf {
    let stem = request
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    match status {
        Some(code) => request.with_file_name(format!("{stem}.{code}.example.json")),
        None => request.with_file_name(format!("{stem}.example.json")),
    }
}

/// Builds routes from request files that have saved examples.
pub fn routes_from_examples(project: &Project) -> Result<Vec<Route>> {
    let mut routes = Vec::new();
    for file in crate::curlconf::find_requests(&project.root, &project.root)? {
        let rel = file.strip_prefix(&project.root)?.to_path_buf();
        if rel.extension().is_none_or(|e| e != "curl") {
            continue;
        }
        let dir = project.root.join(rel.parent().unwrap_or(Path::new("")));
        let stem = rel
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut responses = Vec::new();
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(middle) = name
                .strip_prefix(&format!("{stem}."))
                .and_then(|n| n.strip_suffix("example.json"))
            else {
                continue;
            };
            if !(middle.is_empty() || middle.trim_end_matches('.').parse::<u16>().is_ok()) {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())?;
            let canned: Canned = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", entry.path().display()))?;
            responses.push((middle.is_empty(), canned));
        }
        if responses.is_empty() {
            continue;
        }
        responses.sort_by_key(|(default, c)| (!default, c.status));
        let spec = RequestSpec::load(&project.root, &rel)?;
        routes.push(Route {
            method: spec.method.clone(),
            segments: template_from_url(spec.url.as_deref().unwrap_or("/")),
            label: rel.display().to_string(),
            source: "examples",
            responses: responses.into_iter().map(|(_, c)| c).collect(),
            body_schema: None,
            required_query: vec![],
        });
    }
    Ok(routes)
}

/// Why no route matched.
#[derive(Debug, PartialEq, Eq)]
pub enum Miss {
    /// No route has this path.
    NotFound,
    /// The path exists with other methods.
    MethodNotAllowed(Vec<String>),
}

/// Finds the most specific route for `method` and `path`.
pub fn find<'a>(routes: &'a [Route], method: &str, path: &str) -> Result<&'a Route, Miss> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let path_matches = |r: &Route| {
        r.segments.len() == parts.len()
            && r.segments.iter().zip(&parts).all(|(s, p)| {
                matches!(s, Segment::Param(_)) || matches!(s, Segment::Literal(l) if l == p)
            })
    };
    let candidates: Vec<&Route> = routes.iter().filter(|r| path_matches(r)).collect();
    if candidates.is_empty() {
        return Err(Miss::NotFound);
    }
    candidates
        .iter()
        .filter(|r| {
            r.method.eq_ignore_ascii_case(method) || (method == "HEAD" && r.method == "GET")
        })
        .max_by_key(|r| r.literal_count())
        .copied()
        .ok_or_else(|| {
            let mut allowed: Vec<String> = candidates.iter().map(|r| r.method.clone()).collect();
            allowed.sort();
            allowed.dedup();
            Miss::MethodNotAllowed(allowed)
        })
}

/// Picks a response: `Prefer: code=NNN` (or `__code=NNN` in the query) selects by status.
pub fn select(route: &Route, prefer_code: Option<u16>) -> Option<&Canned> {
    match prefer_code {
        Some(code) => route.responses.iter().find(|c| c.status == code),
        None => route.responses.first(),
    }
}

/// Server options.
#[derive(Debug, Clone)]
pub struct MockOptions {
    /// Address to bind (must be loopback).
    pub host: IpAddr,
    /// Port (0 = any).
    pub port: u16,
    /// Validate request bodies and required query parameters.
    pub validate: bool,
}

struct MockState {
    routes: Vec<Route>,
    validate: bool,
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec_pretty(&body).unwrap_or_default(),
    )
        .into_response()
}

/// Problems with a request against a route's validation rules.
fn validation_errors(route: &Route, query: &BTreeMap<String, String>, body: &[u8]) -> Vec<String> {
    let mut errors: Vec<String> = route
        .required_query
        .iter()
        .filter(|q| !query.contains_key(*q))
        .map(|q| format!("missing required query parameter `{q}`"))
        .collect();
    if let Some(schema) = &route.body_schema {
        match serde_json::from_slice::<Value>(body) {
            Err(_) => errors.push("request body must be JSON".into()),
            Ok(instance) => match jsonschema::validator_for(schema) {
                Ok(v) => errors.extend(v.iter_errors(&instance).take(5).map(|e| {
                    let at = e.instance_path().to_string();
                    if at.is_empty() {
                        e.to_string()
                    } else {
                        format!("{e} at `{at}`")
                    }
                })),
                Err(e) => errors.push(format!("invalid schema: {e}")),
            },
        }
    }
    errors
}

async fn handle(
    State(state): State<Arc<MockState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let query: BTreeMap<String, String> = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let prefer = headers
        .get("prefer")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split([';', ','])
                .find_map(|p| p.trim().strip_prefix("code="))
                .map(str::to_string)
        })
        .or_else(|| query.get("__code").cloned())
        .and_then(|c| c.parse::<u16>().ok());
    let (response, label) = match find(&state.routes, method.as_str(), uri.path()) {
        Err(Miss::NotFound) => {
            let known: Vec<String> = state
                .routes
                .iter()
                .map(|r| format!("{} {}", r.method, r.path()))
                .collect();
            (
                json_response(
                    StatusCode::NOT_FOUND,
                    json!({"error": "no mock route for this path", "routes": known}),
                ),
                "-".to_string(),
            )
        }
        Err(Miss::MethodNotAllowed(allowed)) => {
            let mut r = json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({"error": "method not allowed", "allowed": allowed}),
            );
            if let Ok(v) = HeaderValue::from_str(&allowed.join(", ")) {
                r.headers_mut().insert(axum::http::header::ALLOW, v);
            }
            (r, "-".to_string())
        }
        Ok(route) => {
            let errors = if state.validate {
                validation_errors(route, &query, &body)
            } else {
                vec![]
            };
            let response = if !errors.is_empty() {
                json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error": "request does not match the spec", "details": errors}),
                )
            } else {
                match select(route, prefer) {
                    None => json_response(
                        StatusCode::NOT_ACCEPTABLE,
                        json!({"error": format!("no {} response for {}", prefer.unwrap_or_default(), route.label), "available": route.responses.iter().map(|c| c.status).collect::<Vec<_>>()}),
                    ),
                    Some(c) => {
                        let mut r = Response::builder()
                            .status(StatusCode::from_u16(c.status).unwrap_or(StatusCode::OK));
                        let mut has_type = false;
                        for (k, v) in &c.headers {
                            has_type |= k.eq_ignore_ascii_case("content-type");
                            if let (Ok(k), Ok(v)) = (
                                HeaderName::from_bytes(k.as_bytes()),
                                HeaderValue::from_str(v),
                            ) {
                                r = r.header(k, v);
                            }
                        }
                        let body = c.body_bytes();
                        if !has_type && !body.is_empty() {
                            r = r.header("content-type", "application/json");
                        }
                        r.header("x-curly-mock", route.label.as_str())
                            .body(axum::body::Body::from(if method == Method::HEAD {
                                vec![]
                            } else {
                                body
                            }))
                            .unwrap_or_default()
                    }
                }
            };
            (response, route.label.clone())
        }
    };
    eprintln!(
        "{} {} -> {} {label} ({:.1} ms)",
        method,
        uri,
        response.status().as_u16(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    response
}

/// Rejects anything that is not a loopback address.
pub fn check_loopback(host: IpAddr) -> Result<()> {
    if !host.is_loopback() {
        bail!("curly mock only binds to loopback addresses (127.0.0.1 or ::1), not {host}");
    }
    Ok(())
}

/// Binds and serves until the process is interrupted. Prints the routes first.
pub fn serve(routes: Vec<Route>, opts: &MockOptions) -> Result<()> {
    check_loopback(opts.host)?;
    if routes.is_empty() {
        bail!(
            "nothing to mock: no operations in the spec and no *.example.json files (save one with `curly history save <id>`)"
        );
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(opts.host, opts.port))
            .await
            .context("binding the mock server")?;
        let addr = listener.local_addr()?;
        eprintln!("curly mock listening on http://{addr} (loopback only; Ctrl-C to stop)");
        for r in &routes {
            let codes: Vec<String> = r.responses.iter().map(|c| c.status.to_string()).collect();
            eprintln!(
                "  {:<7}{:<32}{:<28}{}  [{}]",
                r.method,
                r.path(),
                r.label,
                codes.join(", "),
                r.source
            );
        }
        let state = Arc::new(MockState {
            routes,
            validate: opts.validate,
        });
        let app = axum::Router::new().fallback(handle).with_state(state);
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r##"
openapi: 3.0.3
info: {title: t, version: "1"}
servers: [{url: "https://api.test/v1"}]
paths:
  /users:
    post:
      operationId: createUser
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, required: [name], properties: {name: {type: string}}}
      responses:
        "201": {description: ok, content: {application/json: {schema: {type: object, properties: {id: {type: integer}}}}}}
  /users/{id}:
    get:
      operationId: getUser
      parameters: [{name: verbose, in: query, required: true, schema: {type: boolean}}]
      responses:
        "404": {description: no, content: {application/json: {example: {error: "not found"}}}}
        "200": {description: ok, content: {application/json: {schema: {type: object, properties: {id: {type: integer, minimum: 7}}}}}}
  /users/me:
    get:
      operationId: me
      responses:
        "200": {description: ok, content: {text/plain: {example: "hello"}}}
"##;

    #[test]
    fn builds_routes_from_spec() {
        let routes = routes_from_spec(SPEC).unwrap();
        let get = routes.iter().find(|r| r.label == "getUser").unwrap();
        assert_eq!(get.path(), "/v1/users/{id}", "server base path is kept");
        assert_eq!(
            get.responses.iter().map(|c| c.status).collect::<Vec<_>>(),
            vec![200, 404],
            "2xx first"
        );
        assert_eq!(get.responses[0].body, json!({"id": 7}));
        assert_eq!(
            select(get, Some(404)).unwrap().body,
            json!({"error": "not found"})
        );
        assert!(select(get, Some(418)).is_none());
        let me = routes.iter().find(|r| r.label == "me").unwrap();
        assert_eq!(me.responses[0].body_bytes(), b"hello");
    }

    #[test]
    fn matches_most_specific_route() {
        let routes = routes_from_spec(SPEC).unwrap();
        assert_eq!(
            find(&routes, "GET", "/v1/users/me").unwrap().label,
            "me",
            "literal segments win"
        );
        assert_eq!(
            find(&routes, "GET", "/v1/users/42").unwrap().label,
            "getUser"
        );
        assert_eq!(
            find(&routes, "HEAD", "/v1/users/42").unwrap().label,
            "getUser"
        );
        assert_eq!(
            find(&routes, "DELETE", "/v1/users/42").unwrap_err(),
            Miss::MethodNotAllowed(vec!["GET".into()])
        );
        assert_eq!(
            find(&routes, "GET", "/v1/nope").unwrap_err(),
            Miss::NotFound
        );
    }

    #[test]
    fn validates_requests() {
        let routes = routes_from_spec(SPEC).unwrap();
        let create = routes.iter().find(|r| r.label == "createUser").unwrap();
        assert!(validation_errors(create, &BTreeMap::new(), br#"{"name":"x"}"#).is_empty());
        assert!(
            validation_errors(create, &BTreeMap::new(), br#"{"nam":"x"}"#)[0]
                .contains("\"name\" is a required property")
        );
        assert_eq!(
            validation_errors(create, &BTreeMap::new(), b"nope"),
            vec!["request body must be JSON"]
        );
        let get = routes.iter().find(|r| r.label == "getUser").unwrap();
        assert_eq!(
            validation_errors(get, &BTreeMap::new(), b""),
            vec!["missing required query parameter `verbose`"]
        );
    }

    #[test]
    fn templates_from_request_urls() {
        assert_eq!(
            template_from_url("{{BASE_URL}}/users/{{user_id:url}}?x=1"),
            vec![
                Segment::Literal("users".into()),
                Segment::Param("user_id".into())
            ]
        );
        assert_eq!(
            template_from_url("https://h:1/a/b"),
            vec![Segment::Literal("a".into()), Segment::Literal("b".into())]
        );
        assert_eq!(
            example_path(Path::new("u/get.curl"), None),
            PathBuf::from("u/get.example.json")
        );
        assert_eq!(
            example_path(Path::new("u/get.curl"), Some(404)),
            PathBuf::from("u/get.404.example.json")
        );
        assert!(check_loopback("0.0.0.0".parse().unwrap()).is_err());
        assert!(check_loopback("::1".parse().unwrap()).is_ok());
    }
}
