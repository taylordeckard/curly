//! Loads OpenAPI 3.x and Swagger 2.0 documents (JSON or YAML) and normalizes
//! them into one model. Only local `$ref`s (`#/...`) are followed.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

/// Maximum `$ref` hops before giving up (guards against ref loops).
const MAX_REF_HOPS: usize = 32;

/// Which specification family the document uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Swagger 2.0.
    Swagger2,
    /// OpenAPI 3.0.x.
    OpenApi30,
    /// OpenAPI 3.1.x.
    OpenApi31,
}

/// A loaded document with `$ref` resolution.
#[derive(Debug, Clone)]
pub struct Spec {
    /// Raw document.
    pub doc: Value,
    /// Detected version.
    pub version: Version,
    /// Whether the source text was JSON (otherwise YAML).
    pub is_json: bool,
}

impl Spec {
    /// Parses JSON or YAML text.
    pub fn parse(text: &str) -> Result<Spec> {
        let trimmed = text.trim_start();
        let is_json = trimmed.starts_with('{');
        let doc: Value = if is_json {
            serde_json::from_str(text).context("parsing JSON spec")?
        } else {
            yaml_serde::from_str(text).context("parsing YAML spec")?
        };
        let version = if doc
            .get("swagger")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with('2'))
        {
            Version::Swagger2
        } else {
            match doc.get("openapi").and_then(Value::as_str) {
                Some(v) if v.starts_with("3.1") => Version::OpenApi31,
                Some(v) if v.starts_with("3.") => Version::OpenApi30,
                _ => bail!(
                    "not an OpenAPI 3.x or Swagger 2.0 document (no `openapi: 3.x` or `swagger: \"2.0\"`)"
                ),
            }
        };
        Ok(Spec {
            doc,
            version,
            is_json,
        })
    }

    /// Looks up a local JSON pointer ref such as `#/components/schemas/Pet`.
    pub fn pointer(&self, r: &str) -> Option<&Value> {
        r.strip_prefix('#').and_then(|p| self.doc.pointer(p))
    }

    /// Follows `$ref` chains; returns the input when it is not a local ref.
    pub fn resolve<'a>(&'a self, mut v: &'a Value) -> &'a Value {
        for _ in 0..MAX_REF_HOPS {
            match v
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|r| self.pointer(r))
            {
                Some(target) => v = target,
                None => return v,
            }
        }
        v
    }
}

/// Where a parameter goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamIn {
    /// URL path segment.
    Path,
    /// Query string.
    Query,
    /// Request header.
    Header,
    /// Cookie.
    Cookie,
}

/// A path/query/header/cookie parameter.
#[derive(Debug, Clone)]
pub struct Param {
    /// Name as written in the spec.
    pub name: String,
    /// Location.
    pub location: ParamIn,
    /// Whether it is required.
    pub required: bool,
    /// Description.
    pub description: Option<String>,
    /// JSON Schema of the value.
    pub schema: Value,
    /// Explicit example, if any.
    pub example: Option<Value>,
}

/// A request or response body for one media type.
#[derive(Debug, Clone)]
pub struct Body {
    /// Media type, e.g. `application/json`.
    pub content_type: String,
    /// Schema (may be a `$ref`).
    pub schema: Option<Value>,
    /// Explicit example from the media type, if any.
    pub example: Option<Value>,
}

/// One documented response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status key: `200`, `2XX`, or `default`.
    pub status: String,
    /// Description.
    pub description: Option<String>,
    /// Preferred body (JSON first), if any.
    pub body: Option<Body>,
    /// All media types offered.
    pub content_types: Vec<String>,
}

/// An API operation.
#[derive(Debug, Clone)]
pub struct Operation {
    /// Upper-case HTTP method.
    pub method: String,
    /// Path template, e.g. `/pets/{petId}`.
    pub path: String,
    /// `operationId`.
    pub operation_id: Option<String>,
    /// Summary.
    pub summary: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Parameters (path-level merged with operation-level).
    pub params: Vec<Param>,
    /// Request body (JSON preferred).
    pub body: Option<Body>,
    /// Whether the body is required.
    pub body_required: bool,
    /// Responses in document order.
    pub responses: Vec<Response>,
    /// Security alternatives; each maps scheme name to scopes. `None` = inherit global.
    pub security: Option<Vec<BTreeMap<String, Vec<String>>>>,
    /// Deprecated flag.
    pub deprecated: bool,
}

/// OAuth 2.0 flow details, kept for documentation and the OAuth milestone.
#[derive(Debug, Clone, PartialEq)]
pub struct OAuthFlow {
    /// `authorizationCode`, `clientCredentials`, `password`, or `implicit`.
    pub kind: String,
    /// Authorization endpoint.
    pub authorization_url: Option<String>,
    /// Token endpoint.
    pub token_url: Option<String>,
    /// Refresh endpoint.
    pub refresh_url: Option<String>,
    /// Scope names.
    pub scopes: Vec<String>,
}

/// A security scheme.
#[derive(Debug, Clone, PartialEq)]
pub enum Scheme {
    /// API key in a header, query parameter, or cookie.
    ApiKey {
        /// Header/parameter/cookie name.
        name: String,
        /// Where it goes.
        location: ParamIn,
    },
    /// HTTP Basic.
    Basic,
    /// HTTP Bearer (or another HTTP scheme with a token).
    Bearer,
    /// OAuth 2.0.
    OAuth2 {
        /// Declared flows.
        flows: Vec<OAuthFlow>,
    },
    /// OpenID Connect discovery.
    OpenIdConnect {
        /// Discovery URL.
        url: String,
    },
}

/// A normalized API.
#[derive(Debug, Clone)]
pub struct Api {
    /// `info.title`.
    pub title: String,
    /// `info.version`.
    pub version: String,
    /// `info.description`.
    pub description: Option<String>,
    /// Server URLs with variables substituted (first is the default).
    pub servers: Vec<(String, Option<String>)>,
    /// Tags with descriptions, in document order.
    pub tags: Vec<(String, String)>,
    /// Operations in document order.
    pub operations: Vec<Operation>,
    /// Security schemes by name.
    pub schemes: BTreeMap<String, Scheme>,
    /// Global security alternatives.
    pub security: Vec<BTreeMap<String, Vec<String>>>,
}

impl Api {
    /// Security alternatives that apply to `op`.
    pub fn security_for<'a>(&'a self, op: &'a Operation) -> &'a [BTreeMap<String, Vec<String>>] {
        op.security.as_deref().unwrap_or(&self.security)
    }
}

const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn param_in(s: &str) -> Option<ParamIn> {
    Some(match s {
        "path" => ParamIn::Path,
        "query" => ParamIn::Query,
        "header" => ParamIn::Header,
        "cookie" => ParamIn::Cookie,
        _ => return None,
    })
}

fn security_list(v: Option<&Value>) -> Option<Vec<BTreeMap<String, Vec<String>>>> {
    let arr = v?.as_array()?;
    Some(
        arr.iter()
            .filter_map(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, scopes)| {
                        (
                            k.clone(),
                            scopes
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(Value::as_str)
                                        .map(str::to_string)
                                        .collect()
                                })
                                .unwrap_or_default(),
                        )
                    })
                    .collect()
            })
            .collect(),
    )
}

/// Picks the JSON media type if offered, else the first.
fn pick_media(content: &Map<String, Value>) -> Option<(String, &Value)> {
    let is_json = |k: &str| k.starts_with("application/json") || k.contains("+json");
    content
        .iter()
        .find(|(k, _)| is_json(k))
        .or_else(|| content.iter().next())
        .map(|(k, v)| (k.clone(), v))
}

/// Example from a 3.x media type object (`example` or the first of `examples`).
fn media_example(spec: &Spec, media: &Value) -> Option<Value> {
    media.get("example").cloned().or_else(|| {
        media
            .get("examples")
            .and_then(Value::as_object)
            .and_then(|m| m.values().next())
            .map(|e| spec.resolve(e))
            .and_then(|e| e.get("value").cloned())
    })
}

/// Substitutes `{var}` server variables with their defaults.
fn server_url(server: &Value) -> String {
    let mut url = text(server, "url").unwrap_or_else(|| "/".into());
    if let Some(vars) = server.get("variables").and_then(Value::as_object) {
        for (name, var) in vars {
            let default = var
                .get("default")
                .map(|d| {
                    d.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| d.to_string())
                })
                .unwrap_or_default();
            url = url.replace(&format!("{{{name}}}"), &default);
        }
    }
    url
}

fn parse_scheme(spec: &Spec, raw: &Value) -> Option<Scheme> {
    let s = spec.resolve(raw);
    let kind = text(s, "type")?;
    Some(match kind.as_str() {
        "apiKey" => Scheme::ApiKey {
            name: text(s, "name")?,
            location: param_in(&text(s, "in")?)?,
        },
        "basic" => Scheme::Basic,
        "http" => match text(s, "scheme")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "basic" => Scheme::Basic,
            _ => Scheme::Bearer,
        },
        "oauth2" => {
            let mut flows = Vec::new();
            let scopes = |f: &Value| {
                f.get("scopes")
                    .and_then(Value::as_object)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default()
            };
            if let Some(map) = s.get("flows").and_then(Value::as_object) {
                for (k, f) in map {
                    flows.push(OAuthFlow {
                        kind: k.clone(),
                        authorization_url: text(f, "authorizationUrl"),
                        token_url: text(f, "tokenUrl"),
                        refresh_url: text(f, "refreshUrl"),
                        scopes: scopes(f),
                    });
                }
            } else {
                let kind = match text(s, "flow").as_deref() {
                    Some("accessCode") => "authorizationCode",
                    Some("application") => "clientCredentials",
                    Some(other) => other,
                    None => "authorizationCode",
                }
                .to_string();
                flows.push(OAuthFlow {
                    kind,
                    authorization_url: text(s, "authorizationUrl"),
                    token_url: text(s, "tokenUrl"),
                    refresh_url: None,
                    scopes: scopes(s),
                });
            }
            Scheme::OAuth2 { flows }
        }
        "openIdConnect" => Scheme::OpenIdConnect {
            url: text(s, "openIdConnectUrl").unwrap_or_default(),
        },
        _ => return None,
    })
}

/// Swagger 2.0 non-body parameters carry their schema inline.
fn swagger_param_schema(p: &Value) -> Value {
    let mut schema = Map::new();
    if let Some(obj) = p.as_object() {
        for (k, v) in obj {
            if !matches!(
                k.as_str(),
                "name"
                    | "in"
                    | "required"
                    | "description"
                    | "allowEmptyValue"
                    | "collectionFormat"
                    | "x-example"
            ) {
                schema.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(schema)
}

/// Normalizes the document into an [`Api`].
pub fn normalize(spec: &Spec) -> Result<Api> {
    let d = &spec.doc;
    let info = d.get("info").cloned().unwrap_or_default();
    let swagger = spec.version == Version::Swagger2;
    let servers = if swagger {
        let scheme = d
            .get("schemes")
            .and_then(|s| s.get(0))
            .and_then(Value::as_str)
            .unwrap_or("https");
        let host = d.get("host").and_then(Value::as_str).unwrap_or("localhost");
        let base = d.get("basePath").and_then(Value::as_str).unwrap_or("");
        vec![(format!("{scheme}://{host}{base}"), None)]
    } else {
        d.get("servers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|s| (server_url(s), text(s, "description")))
                    .collect()
            })
            .unwrap_or_default()
    };
    let tags = d
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    Some((text(t, "name")?, text(t, "description").unwrap_or_default()))
                })
                .collect()
        })
        .unwrap_or_default();
    let schemes_raw = if swagger {
        d.get("securityDefinitions")
    } else {
        d.pointer("/components/securitySchemes")
    };
    let schemes = schemes_raw
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| parse_scheme(spec, v).map(|s| (k.clone(), s)))
                .collect()
        })
        .unwrap_or_default();
    let global_consumes: Vec<String> = d
        .get("consumes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let global_produces: Vec<String> = d
        .get("produces")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut operations = Vec::new();
    for (path, item) in d
        .get("paths")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let item = spec.resolve(item);
        let path_params: Vec<Value> = item
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for method in METHODS {
            let Some(op) = item.get(*method) else {
                continue;
            };
            let mut raw_params: Vec<Value> = Vec::new();
            for p in path_params.iter().chain(
                op.get("parameters")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            ) {
                let p = spec.resolve(p).clone();
                raw_params
                    .retain(|q| !(q.get("name") == p.get("name") && q.get("in") == p.get("in")));
                raw_params.push(p);
            }
            let consumes: Vec<String> = op
                .get("consumes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| global_consumes.clone());
            let produces: Vec<String> = op
                .get("produces")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| global_produces.clone());
            let mut params = Vec::new();
            let mut body = None;
            let mut body_required = false;
            let mut form_props = Map::new();
            let mut form_required = Vec::new();
            for p in &raw_params {
                let name = text(p, "name").unwrap_or_default();
                let location = text(p, "in").unwrap_or_default();
                if swagger && location == "body" {
                    let ct = consumes
                        .iter()
                        .find(|c| c.contains("json"))
                        .cloned()
                        .unwrap_or_else(|| "application/json".into());
                    body = Some(Body {
                        content_type: ct,
                        schema: p.get("schema").cloned(),
                        example: p.get("x-example").cloned(),
                    });
                    body_required = p.get("required").and_then(Value::as_bool).unwrap_or(false);
                    continue;
                }
                if swagger && location == "formData" {
                    form_props.insert(name.clone(), swagger_param_schema(p));
                    if p.get("required").and_then(Value::as_bool).unwrap_or(false) {
                        form_required.push(Value::String(name));
                    }
                    continue;
                }
                let Some(loc) = param_in(&location) else {
                    continue;
                };
                let schema = if swagger {
                    swagger_param_schema(p)
                } else {
                    p.get("schema").cloned().unwrap_or(json!({}))
                };
                let example = p
                    .get("example")
                    .cloned()
                    .or_else(|| p.get("x-example").cloned())
                    .or_else(|| media_example(spec, p));
                params.push(Param {
                    name,
                    location: loc,
                    required: loc == ParamIn::Path
                        || p.get("required").and_then(Value::as_bool).unwrap_or(false),
                    description: text(p, "description"),
                    schema,
                    example,
                });
            }
            if swagger && !form_props.is_empty() {
                body_required = !form_required.is_empty();
                let ct = consumes
                    .iter()
                    .find(|c| c.contains("form"))
                    .cloned()
                    .unwrap_or_else(|| "application/x-www-form-urlencoded".into());
                body = Some(Body {
                    content_type: ct,
                    schema: Some(
                        json!({"type": "object", "properties": form_props, "required": form_required}),
                    ),
                    example: None,
                });
            }
            if !swagger && let Some(rb) = op.get("requestBody").map(|b| spec.resolve(b)) {
                body_required = rb.get("required").and_then(Value::as_bool).unwrap_or(false);
                if let Some((ct, media)) = rb
                    .get("content")
                    .and_then(Value::as_object)
                    .and_then(pick_media)
                {
                    body = Some(Body {
                        content_type: ct,
                        schema: media.get("schema").cloned(),
                        example: media_example(spec, media),
                    });
                }
            }
            let mut responses = Vec::new();
            for (status, r) in op
                .get("responses")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let r = spec.resolve(r);
                let (body, content_types) = if swagger {
                    let ct = produces
                        .iter()
                        .find(|c| c.contains("json"))
                        .cloned()
                        .or_else(|| produces.first().cloned())
                        .unwrap_or_else(|| "application/json".into());
                    let example = r.get("examples").and_then(|e| e.get(&ct)).cloned();
                    (
                        r.get("schema").map(|s| Body {
                            content_type: ct,
                            schema: Some(s.clone()),
                            example,
                        }),
                        produces.clone(),
                    )
                } else {
                    let content = r.get("content").and_then(Value::as_object);
                    let body = content.and_then(pick_media).map(|(ct, m)| Body {
                        content_type: ct,
                        schema: m.get("schema").cloned(),
                        example: media_example(spec, m),
                    });
                    (
                        body,
                        content
                            .map(|c| c.keys().cloned().collect())
                            .unwrap_or_default(),
                    )
                };
                responses.push(Response {
                    status: status.clone(),
                    description: text(r, "description"),
                    body,
                    content_types,
                });
            }
            operations.push(Operation {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                operation_id: text(op, "operationId"),
                summary: text(op, "summary"),
                description: text(op, "description"),
                tags: op
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                params,
                body,
                body_required,
                responses,
                security: security_list(op.get("security")),
                deprecated: op
                    .get("deprecated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            });
        }
    }
    Ok(Api {
        title: text(&info, "title").unwrap_or_else(|| "API".into()),
        version: text(&info, "version").unwrap_or_default(),
        description: text(&info, "description"),
        servers,
        tags,
        operations,
        schemes,
        security: security_list(d.get("security")).unwrap_or_default(),
    })
}
