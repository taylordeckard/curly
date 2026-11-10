//! GraphQL requests: plain `.curl` files that read a `.graphql` document and a
//! variables JSON file through request-local curl variables:
//!
//! ```text
//! variable = "GQL_QUERY@graphql/get-user.graphql"
//! variable = "GQL_VARS@graphql/get-user.vars.json"
//! expand-url = "{{BASE_URL}}/graphql"
//! header = "Content-Type: application/json"
//! expand-data = "{\"query\":\"{{GQL_QUERY:json}}\",\"variables\":{{GQL_VARS}}}"
//! ```
//!
//! curly introspects the endpoint (with the request's own headers and auth),
//! caches the schema per endpoint URL, converts it to SDL, and validates
//! documents with `apollo-compiler`. It also completes fields at a cursor
//! position and generates new requests from the schema.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use apollo_compiler::{ExecutableDocument, Schema};
use regex::Regex;
use serde_json::{Value, json};

use crate::curlconf::{RequestSpec, quote, substitute};
use crate::project::Project;
use crate::request::sha256_hex;
use crate::vars::{Layers, VarContext, parse_variable_arg};

/// The standard introspection query (types, fields, args, enums, inputs, directives).
pub const INTROSPECTION_QUERY: &str = r#"query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
"#;

/// Built-in scalars and directives that SDL must not redeclare.
const BUILTIN_SCALARS: &[&str] = &["String", "Int", "Float", "Boolean", "ID"];
const BUILTIN_DIRECTIVES: &[&str] = &[
    "skip",
    "include",
    "deprecated",
    "specifiedBy",
    "oneOf",
    "defer",
    "stream",
];

/// A GraphQL request's document file and variables file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlFiles {
    /// Collection-relative `.graphql` file.
    pub document: PathBuf,
    /// Collection-relative variables JSON file, if any.
    pub variables: Option<PathBuf>,
}

/// Returns the GraphQL files a request reads, if it is a GraphQL request
/// (it defines a variable from a `.graphql`/`.gql` file).
pub fn graphql_files(spec: &RequestSpec) -> Option<GraphqlFiles> {
    let mut document = None;
    let mut variables = None;
    for (_, arg) in &spec.variables {
        if let Ok((_, crate::vars::Source::File { path })) = parse_variable_arg(arg) {
            if path.ends_with(".graphql") || path.ends_with(".gql") {
                document = Some(PathBuf::from(path));
            } else if path.ends_with(".json") {
                variables = Some(PathBuf::from(path));
            }
        }
    }
    document.map(|document| GraphqlFiles {
        document,
        variables,
    })
}

/// Expands the request URL with `vars` (unknown functions such as `:url` are applied as-is).
pub fn endpoint(spec: &RequestSpec, vars: &BTreeMap<String, String>) -> Result<String> {
    let url = spec.url.clone().context("request has no url")?;
    let plain = Regex::new(r"\{\{([A-Za-z0-9_]+)(:[A-Za-z0-9:]+)?\}\}")
        .expect("regex")
        .replace_all(&url, "{{$1}}")
        .into_owned();
    substitute(&plain, vars)
        .map_err(|e| anyhow::anyhow!("cannot determine the GraphQL endpoint: {e}"))
}

/// Variable values for endpoint expansion (no secret store access).
fn plain_values(
    project: &Project,
    rel: &Path,
    env: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let layers = Layers {
        folder: crate::folder::folder_vars(project, rel)?,
        ..Default::default()
    };
    Ok(VarContext::build(project, env, &layers, None)?.values(&project.root))
}

/// Endpoint of the GraphQL request `rel`.
pub fn request_endpoint(project: &Project, rel: &Path, env: Option<&str>) -> Result<String> {
    endpoint(
        &RequestSpec::load(&project.root, rel)?,
        &plain_values(project, rel, env)?,
    )
}

fn cache_path(project: &Project, endpoint: &str) -> Result<PathBuf> {
    let dir = project.state_dir()?.join("cache").join("graphql");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{}.json", &sha256_hex(endpoint.as_bytes())[..16])))
}

/// A cached introspection result.
#[derive(Debug, Clone)]
pub struct CachedSchema {
    /// Endpoint URL.
    pub endpoint: String,
    /// When it was fetched (RFC 3339).
    pub fetched_at: String,
    /// `data.__schema` from the introspection response.
    pub schema: Value,
}

/// Saves an introspection response (`{"data": {"__schema": ...}}`).
pub fn save_schema(project: &Project, endpoint: &str, response: &Value) -> Result<PathBuf> {
    let schema = response
        .pointer("/data/__schema")
        .cloned()
        .context("introspection response has no data.__schema (is introspection disabled?)")?;
    let path = cache_path(project, endpoint)?;
    let doc = json!({"endpoint": endpoint, "fetched_at": chrono::Utc::now().to_rfc3339(), "schema": schema});
    std::fs::write(&path, serde_json::to_string(&doc)?)?;
    Ok(path)
}

/// Loads the cached schema for `endpoint`, if any (never creates `.curly/`).
pub fn load_schema(project: &Project, endpoint: &str) -> Result<Option<CachedSchema>> {
    let path = project
        .root
        .join(crate::project::STATE_DIR)
        .join("cache/graphql")
        .join(format!("{}.json", &sha256_hex(endpoint.as_bytes())[..16]));
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(CachedSchema {
        endpoint: v["endpoint"].as_str().unwrap_or_default().into(),
        fetched_at: v["fetched_at"].as_str().unwrap_or_default().into(),
        schema: v["schema"].clone(),
    }))
}

/// Every cached schema.
pub fn cached_schemas(project: &Project) -> Vec<CachedSchema> {
    let dir = project
        .root
        .join(crate::project::STATE_DIR)
        .join("cache/graphql");
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if let Ok(v) = std::fs::read_to_string(e.path())
            .map(|t| serde_json::from_str::<Value>(&t).unwrap_or_default())
        {
            out.push(CachedSchema {
                endpoint: v["endpoint"].as_str().unwrap_or_default().into(),
                fetched_at: v["fetched_at"].as_str().unwrap_or_default().into(),
                schema: v["schema"].clone(),
            });
        }
    }
    out
}

/// The JSON body of an introspection request.
pub fn introspection_body() -> String {
    json!({"query": INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"}).to_string()
}

/// Renders a `__Type` reference (`[User!]!`).
fn type_ref(t: &Value) -> String {
    match t["kind"].as_str() {
        Some("NON_NULL") => format!("{}!", type_ref(&t["ofType"])),
        Some("LIST") => format!("[{}]", type_ref(&t["ofType"])),
        _ => t["name"].as_str().unwrap_or("Unknown").to_string(),
    }
}

/// Innermost named type of a reference.
fn named_type(t: &Value) -> String {
    match t["kind"].as_str() {
        Some("NON_NULL") | Some("LIST") => named_type(&t["ofType"]),
        _ => t["name"].as_str().unwrap_or_default().to_string(),
    }
}

fn description(out: &mut String, indent: &str, d: &Value) {
    if let Some(d) = d.as_str().filter(|d| !d.is_empty()) {
        let _ = writeln!(
            out,
            "{indent}\"\"\"{}\"\"\"",
            d.replace("\"\"\"", "\\\"\"\"")
        );
    }
}

fn args_sdl(args: &Value) -> String {
    let args: Vec<String> = args
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let default = a["defaultValue"]
                .as_str()
                .map(|d| format!(" = {d}"))
                .unwrap_or_default();
            format!(
                "{}: {}{default}",
                a["name"].as_str().unwrap_or_default(),
                type_ref(&a["type"])
            )
        })
        .collect();
    if args.is_empty() {
        String::new()
    } else {
        format!("({})", args.join(", "))
    }
}

fn deprecated(v: &Value) -> String {
    if v["isDeprecated"].as_bool() == Some(true) {
        match v["deprecationReason"].as_str() {
            Some(r) => format!(
                " @deprecated(reason: {})",
                serde_json::to_string(r).unwrap_or_default()
            ),
            None => " @deprecated".into(),
        }
    } else {
        String::new()
    }
}

/// Converts `__schema` introspection JSON into SDL.
pub fn to_sdl(schema: &Value) -> String {
    let mut out = String::new();
    let roots: Vec<String> = [
        ("query", "queryType"),
        ("mutation", "mutationType"),
        ("subscription", "subscriptionType"),
    ]
    .iter()
    .filter_map(|(op, key)| schema[key]["name"].as_str().map(|n| format!("  {op}: {n}")))
    .collect();
    let _ = writeln!(out, "schema {{\n{}\n}}\n", roots.join("\n"));
    for d in schema["directives"].as_array().into_iter().flatten() {
        let name = d["name"].as_str().unwrap_or_default();
        if BUILTIN_DIRECTIVES.contains(&name) {
            continue;
        }
        description(&mut out, "", &d["description"]);
        let locations: Vec<&str> = d["locations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let _ = writeln!(
            out,
            "directive @{name}{} on {}\n",
            args_sdl(&d["args"]),
            locations.join(" | ")
        );
    }
    for t in schema["types"].as_array().into_iter().flatten() {
        let name = t["name"].as_str().unwrap_or_default();
        if name.starts_with("__") || BUILTIN_SCALARS.contains(&name) {
            continue;
        }
        description(&mut out, "", &t["description"]);
        let interfaces: Vec<String> = t["interfaces"]
            .as_array()
            .into_iter()
            .flatten()
            .map(type_ref)
            .collect();
        let implements = if interfaces.is_empty() {
            String::new()
        } else {
            format!(" implements {}", interfaces.join(" & "))
        };
        match t["kind"].as_str().unwrap_or_default() {
            "SCALAR" => {
                let _ = writeln!(out, "scalar {name}\n");
            }
            kind @ ("OBJECT" | "INTERFACE") => {
                let keyword = if kind == "OBJECT" {
                    "type"
                } else {
                    "interface"
                };
                let _ = writeln!(out, "{keyword} {name}{implements} {{");
                for f in t["fields"].as_array().into_iter().flatten() {
                    description(&mut out, "  ", &f["description"]);
                    let _ = writeln!(
                        out,
                        "  {}{}: {}{}",
                        f["name"].as_str().unwrap_or_default(),
                        args_sdl(&f["args"]),
                        type_ref(&f["type"]),
                        deprecated(f)
                    );
                }
                out.push_str("}\n\n");
            }
            "UNION" => {
                let members: Vec<String> = t["possibleTypes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(type_ref)
                    .collect();
                let _ = writeln!(out, "union {name} = {}\n", members.join(" | "));
            }
            "ENUM" => {
                let _ = writeln!(out, "enum {name} {{");
                for v in t["enumValues"].as_array().into_iter().flatten() {
                    let _ = writeln!(
                        out,
                        "  {}{}",
                        v["name"].as_str().unwrap_or_default(),
                        deprecated(v)
                    );
                }
                out.push_str("}\n\n");
            }
            "INPUT_OBJECT" => {
                let _ = writeln!(out, "input {name} {{");
                for f in t["inputFields"].as_array().into_iter().flatten() {
                    let default = f["defaultValue"]
                        .as_str()
                        .map(|d| format!(" = {d}"))
                        .unwrap_or_default();
                    let _ = writeln!(
                        out,
                        "  {}: {}{default}",
                        f["name"].as_str().unwrap_or_default(),
                        type_ref(&f["type"])
                    );
                }
                out.push_str("}\n\n");
            }
            _ => {}
        }
    }
    out
}

/// A validation problem in a GraphQL document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GqlDiagnostic {
    /// 1-based line (0 when unknown).
    pub line: usize,
    /// 1-based column (0 when unknown).
    pub column: usize,
    /// Message.
    pub message: String,
}

impl GqlDiagnostic {
    /// `file:line:col` (or just `file` when the position is unknown).
    pub fn location(&self, file: &Path) -> String {
        if self.line == 0 {
            file.display().to_string()
        } else {
            format!("{}:{}:{}", file.display(), self.line, self.column)
        }
    }
}

/// Matches operation variable definitions such as `$id: ID!` or `$n: Int = 3`.
static VAR_DEF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_\[\]!0-9 ]+?)\s*(=|[,)\$])")
        .expect("regex")
});

/// Validates `document` against the introspected `schema`; also checks that
/// required operation variables are present in `variables` (a JSON object).
pub fn validate(
    schema: &Value,
    document: &str,
    doc_path: &Path,
    variables: Option<&Value>,
) -> Result<Vec<GqlDiagnostic>> {
    let sdl = to_sdl(schema);
    let schema = match Schema::parse_and_validate(sdl, "introspection.graphql") {
        Ok(s) => s,
        Err(e) => bail!(
            "the cached schema could not be loaded: {}",
            e.errors
                .iter()
                .map(|d| d.to_json().message)
                .collect::<Vec<_>>()
                .join("; ")
        ),
    };
    let mut out = Vec::new();
    if let Err(e) = ExecutableDocument::parse_and_validate(&schema, document, doc_path) {
        for d in e.errors.iter() {
            let pos = d
                .line_column_range()
                .map(|r| (r.start.line, r.start.column))
                .unwrap_or((0, 0));
            out.push(GqlDiagnostic {
                line: pos.0,
                column: pos.1,
                message: d.to_json().message,
            });
        }
    }
    if let Some(vars) = variables {
        let header = document.split('{').next().unwrap_or_default();
        for c in VAR_DEF.captures_iter(header) {
            let (name, ty, after) = (&c[1], c[2].trim(), &c[3]);
            if ty.ends_with('!') && after != "=" && vars.get(name).is_none_or(Value::is_null) {
                out.push(GqlDiagnostic {
                    line: 0,
                    column: 0,
                    message: format!(
                        "required variable `${name}: {ty}` is missing from the variables file"
                    ),
                });
            }
        }
    }
    Ok(out)
}

/// Field info used by completion and generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldInfo {
    /// Field name.
    pub name: String,
    /// Type reference, e.g. `[User!]!`.
    pub ty: String,
    /// Description.
    pub description: String,
}

fn find_type<'a>(schema: &'a Value, name: &str) -> Option<&'a Value> {
    schema["types"]
        .as_array()?
        .iter()
        .find(|t| t["name"].as_str() == Some(name))
}

/// Fields of the object/interface type `name`.
pub fn fields_of(schema: &Value, name: &str) -> Vec<FieldInfo> {
    find_type(schema, name)
        .and_then(|t| t["fields"].as_array())
        .into_iter()
        .flatten()
        .map(|f| FieldInfo {
            name: f["name"].as_str().unwrap_or_default().into(),
            ty: type_ref(&f["type"]),
            description: f["description"].as_str().unwrap_or_default().into(),
        })
        .collect()
}

/// Root type names: (query, mutation, subscription).
fn root_type(schema: &Value, op: &str) -> Option<String> {
    let key = match op {
        "mutation" => "mutationType",
        "subscription" => "subscriptionType",
        _ => "queryType",
    };
    schema[key]["name"].as_str().map(str::to_string)
}

/// Field completions at a cursor position (1-based line and column) in `document`.
pub fn complete_at(schema: &Value, document: &str, line: usize, column: usize) -> Vec<FieldInfo> {
    let offset: usize = document
        .split_inclusive('\n')
        .take(line.saturating_sub(1))
        .map(str::len)
        .sum::<usize>()
        + document
            .lines()
            .nth(line.saturating_sub(1))
            .map(|l| {
                l.chars()
                    .take(column.saturating_sub(1))
                    .map(char::len_utf8)
                    .sum()
            })
            .unwrap_or(0);
    let before = &document[..offset.min(document.len())];
    enum Frame {
        Field(String),
        Type(String),
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut last_name: Option<String> = None;
    let mut pending_type: Option<String> = None;
    let mut root: Option<String> = None;
    let mut paren = 0usize;
    let mut words: Vec<String> = Vec::new();
    let mut chars = before.chars().peekable();
    let mut prefix = String::new();
    while let Some(c) = chars.next() {
        match c {
            '#' => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '"' => {
                for c in chars.by_ref() {
                    if c == '"' {
                        break;
                    }
                }
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '{' if paren == 0 => {
                let frame = if stack.is_empty() {
                    let ty = pending_type
                        .take()
                        .or_else(|| root_type(schema, root.as_deref().unwrap_or("query")));
                    Frame::Type(ty.unwrap_or_default())
                } else if let Some(t) = pending_type.take() {
                    Frame::Type(t)
                } else {
                    Frame::Field(last_name.clone().unwrap_or_default())
                };
                stack.push(frame);
                last_name = None;
            }
            '}' if paren == 0 => {
                stack.pop();
                last_name = None;
            }
            c if c.is_alphanumeric() || c == '_' => {
                let mut w = String::from(c);
                while let Some(&n) = chars.peek() {
                    if n.is_alphanumeric() || n == '_' {
                        w.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if chars.peek().is_none() {
                    prefix = w.clone();
                }
                if paren == 0 {
                    if stack.is_empty()
                        && root.is_none()
                        && ["query", "mutation", "subscription"].contains(&w.as_str())
                    {
                        root = Some(w.clone());
                    }
                    if words.last().map(String::as_str) == Some("on") {
                        pending_type = Some(w.clone());
                    } else if w != "on" && w != "fragment" {
                        last_name = Some(w.clone());
                    }
                    words.push(w);
                }
            }
            _ => {}
        }
    }
    let mut ty = String::new();
    for f in &stack {
        ty = match f {
            Frame::Type(t) => t.clone(),
            Frame::Field(name) => fields_of(schema, &ty)
                .into_iter()
                .find(|fi| &fi.name == name)
                .map(|fi| {
                    fi.ty
                        .trim_matches(|c| c == '[' || c == ']' || c == '!')
                        .to_string()
                })
                .unwrap_or_default(),
        };
    }
    if stack.is_empty() || ty.is_empty() {
        return vec![];
    }
    let mut fields = fields_of(schema, &ty);
    fields.push(FieldInfo {
        name: "__typename".into(),
        ty: "String!".into(),
        description: "Name of the object type".into(),
    });
    fields
        .into_iter()
        .filter(|f| f.name.starts_with(&prefix))
        .collect()
}

/// Example JSON value for a GraphQL input type reference.
fn example_input(schema: &Value, t: &Value, depth: usize) -> Value {
    match t["kind"].as_str() {
        Some("NON_NULL") => example_input(schema, &t["ofType"], depth),
        Some("LIST") => json!([example_input(schema, &t["ofType"], depth)]),
        _ => {
            let name = t["name"].as_str().unwrap_or_default();
            match name {
                "ID" => json!("1"),
                "Int" => json!(1),
                "Float" => json!(1.5),
                "Boolean" => json!(true),
                "String" => json!("string"),
                _ => match find_type(schema, name) {
                    Some(ty) if ty["kind"] == "ENUM" => ty["enumValues"][0]["name"].clone(),
                    Some(ty) if ty["kind"] == "INPUT_OBJECT" && depth < 4 => Value::Object(
                        ty["inputFields"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|f| {
                                (
                                    f["name"].as_str().unwrap_or_default().to_string(),
                                    example_input(schema, &f["type"], depth + 1),
                                )
                            })
                            .collect(),
                    ),
                    _ => json!("string"),
                },
            }
        }
    }
}

/// Generated document and variables for `Type.field`.
#[derive(Debug, Clone)]
pub struct Generated {
    /// GraphQL document.
    pub document: String,
    /// Variables JSON.
    pub variables: Value,
}

/// Builds an operation calling root field `type_field` (`Query.user`) that
/// selects the scalar and enum fields of its return type.
pub fn generate(schema: &Value, type_field: &str) -> Result<Generated> {
    let (type_name, field_name) = type_field
        .split_once('.')
        .context("--field must look like Query.user or Mutation.createUser")?;
    let (op, type_name) = [
        ("query", "queryType"),
        ("mutation", "mutationType"),
        ("subscription", "subscriptionType"),
    ]
    .iter()
    .find_map(|(op, key)| {
        let actual = schema[key]["name"].as_str()?;
        (actual == type_name || type_name.eq_ignore_ascii_case(op))
            .then(|| (*op, actual.to_string()))
    })
    .with_context(|| format!("`{type_name}` is not a root operation type"))?;
    let ty = find_type(schema, &type_name).context("type not found")?;
    let field = ty["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|f| f["name"].as_str() == Some(field_name))
        .with_context(|| format!("`{type_name}` has no field `{field_name}`"))?;
    let args: Vec<&Value> = field["args"].as_array().into_iter().flatten().collect();
    let op_name: String = field_name
        .chars()
        .take(1)
        .flat_map(char::to_uppercase)
        .chain(field_name.chars().skip(1))
        .collect();
    let mut doc = format!("{op} {op_name}");
    if !args.is_empty() {
        let defs: Vec<String> = args
            .iter()
            .map(|a| {
                format!(
                    "${}: {}",
                    a["name"].as_str().unwrap_or_default(),
                    type_ref(&a["type"])
                )
            })
            .collect();
        let _ = write!(doc, "({})", defs.join(", "));
    }
    doc.push_str(" {\n  ");
    doc.push_str(field_name);
    if !args.is_empty() {
        let uses: Vec<String> = args
            .iter()
            .map(|a| format!("{0}: ${0}", a["name"].as_str().unwrap_or_default()))
            .collect();
        let _ = write!(doc, "({})", uses.join(", "));
    }
    let ret = named_type(&field["type"]);
    let scalars: Vec<String> = find_type(schema, &ret)
        .filter(|t| matches!(t["kind"].as_str(), Some("OBJECT" | "INTERFACE")))
        .map(|t| {
            t["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|f| {
                    let inner = named_type(&f["type"]);
                    f["args"]
                        .as_array()
                        .is_none_or(|a| a.iter().all(|x| x["type"]["kind"] != "NON_NULL"))
                        && (BUILTIN_SCALARS.contains(&inner.as_str())
                            || find_type(schema, &inner).is_some_and(|t| {
                                matches!(t["kind"].as_str(), Some("SCALAR" | "ENUM"))
                            }))
                })
                .map(|f| f["name"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    if scalars.is_empty()
        && find_type(schema, &ret)
            .is_some_and(|t| matches!(t["kind"].as_str(), Some("OBJECT" | "INTERFACE" | "UNION")))
    {
        doc.push_str(" {\n    __typename\n  }");
    } else if !scalars.is_empty() {
        let _ = write!(
            doc,
            " {{\n{}\n  }}",
            scalars
                .iter()
                .map(|s| format!("    {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    doc.push_str("\n}\n");
    let variables = Value::Object(
        args.iter()
            .map(|a| {
                (
                    a["name"].as_str().unwrap_or_default().to_string(),
                    example_input(schema, &a["type"], 0),
                )
            })
            .collect(),
    );
    Ok(Generated {
        document: doc,
        variables,
    })
}

/// The `.curl` text for a GraphQL request using `document` and `variables` files.
pub fn request_text(
    name: &str,
    url_template: &str,
    document: &Path,
    variables: &Path,
    extra_lines: &[String],
) -> String {
    let mut out = format!("# @name {name}\n# @tags graphql\n");
    let _ = writeln!(
        out,
        "variable = {}",
        quote(&format!("GQL_QUERY@{}", document.display()))
    );
    let _ = writeln!(
        out,
        "variable = {}",
        quote(&format!("GQL_VARS@{}", variables.display()))
    );
    let _ = writeln!(out, "expand-url = {}", quote(url_template));
    out.push_str(
        "header = \"Content-Type: application/json\"\nheader = \"Accept: application/json\"\n",
    );
    for l in extra_lines {
        let _ = writeln!(out, "{l}");
    }
    out.push_str("expand-data = \"{\\\"query\\\":\\\"{{GQL_QUERY:json}}\\\",\\\"variables\\\":{{GQL_VARS}}}\"\n");
    crate::curlconf::format_flags(&out)
}

/// Result of checking one GraphQL request against its cached schema.
#[derive(Debug, Clone)]
pub struct RequestCheck {
    /// Document file (collection-relative).
    pub document: PathBuf,
    /// Endpoint the schema came from.
    pub endpoint: String,
    /// Problems found.
    pub diagnostics: Vec<GqlDiagnostic>,
}

/// Validates a GraphQL request's document and variables. Returns `None` when
/// `spec` is not a GraphQL request or no schema is cached for its endpoint.
pub fn check_request(
    project: &Project,
    spec: &RequestSpec,
    vars: &BTreeMap<String, String>,
) -> Result<Option<RequestCheck>> {
    let Some(files) = graphql_files(spec) else {
        return Ok(None);
    };
    let endpoint = endpoint(spec, vars)?;
    let Some(cached) = load_schema(project, &endpoint)? else {
        return Ok(None);
    };
    let document = std::fs::read_to_string(project.root.join(&files.document))
        .with_context(|| format!("reading {}", files.document.display()))?;
    let variables = match &files.variables {
        Some(v) => Some(
            serde_json::from_str::<Value>(
                &std::fs::read_to_string(project.root.join(v))
                    .with_context(|| format!("reading {}", v.display()))?,
            )
            .with_context(|| format!("{} is not valid JSON", v.display()))?,
        ),
        None => None,
    };
    let diagnostics = validate(
        &cached.schema,
        &document,
        &files.document,
        variables.as_ref(),
    )?;
    Ok(Some(RequestCheck {
        document: files.document,
        endpoint,
        diagnostics,
    }))
}

/// Every GraphQL request in the collection, as `(request, files)`.
pub fn graphql_requests(project: &Project) -> Vec<(PathBuf, GraphqlFiles)> {
    crate::curlconf::find_requests(&project.root, &project.root)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| {
            let rel = f.strip_prefix(&project.root).ok()?.to_path_buf();
            let spec = RequestSpec::load(&project.root, &rel).ok()?;
            graphql_files(&spec).map(|g| (rel, g))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed introspection result for a small schema.
    pub fn sample_schema() -> Value {
        let scalar = |n: &str| json!({"kind": "SCALAR", "name": n, "ofType": null});
        let nn = |t: Value| json!({"kind": "NON_NULL", "name": null, "ofType": t});
        let list = |t: Value| json!({"kind": "LIST", "name": null, "ofType": t});
        let obj = |n: &str| json!({"kind": "OBJECT", "name": n, "ofType": null});
        let field = |name: &str, ty: Value, args: Value| json!({"name": name, "description": null, "args": args, "type": ty, "isDeprecated": false, "deprecationReason": null});
        let arg = |name: &str, ty: Value| json!({"name": name, "description": null, "type": ty, "defaultValue": null});
        json!({
            "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "subscriptionType": null,
            "directives": [],
            "types": [
                {"kind": "OBJECT", "name": "Query", "description": null, "interfaces": [], "fields": [
                    field("user", obj("User"), json!([arg("id", nn(scalar("ID")))])),
                    field("users", nn(list(nn(obj("User")))), json!([arg("limit", scalar("Int"))])),
                ]},
                {"kind": "OBJECT", "name": "Mutation", "description": null, "interfaces": [], "fields": [
                    field("createUser", nn(obj("User")), json!([arg("input", nn(json!({"kind": "INPUT_OBJECT", "name": "NewUserInput", "ofType": null})))])),
                ]},
                {"kind": "OBJECT", "name": "User", "description": "A user", "interfaces": [], "fields": [
                    field("id", nn(scalar("ID")), json!([])),
                    field("name", nn(scalar("String")), json!([])),
                    field("role", json!({"kind": "ENUM", "name": "Role", "ofType": null}), json!([])),
                    field("friends", nn(list(nn(obj("User")))), json!([arg("first", scalar("Int"))])),
                ]},
                {"kind": "ENUM", "name": "Role", "description": null, "enumValues": [{"name": "ADMIN", "isDeprecated": false}, {"name": "USER", "isDeprecated": true, "deprecationReason": "use ADMIN"}]},
                {"kind": "INPUT_OBJECT", "name": "NewUserInput", "description": null, "inputFields": [arg("name", nn(scalar("String"))), arg("role", json!({"kind": "ENUM", "name": "Role", "ofType": null}))]},
                {"kind": "SCALAR", "name": "String"}, {"kind": "SCALAR", "name": "ID"}, {"kind": "SCALAR", "name": "Int"}, {"kind": "SCALAR", "name": "Boolean"},
                {"kind": "OBJECT", "name": "__Type", "fields": []}
            ]
        })
    }

    #[test]
    fn converts_introspection_to_valid_sdl() {
        let sdl = to_sdl(&sample_schema());
        assert!(
            sdl.contains("type Query {\n  user(id: ID!): User\n  users(limit: Int): [User!]!\n}"),
            "{sdl}"
        );
        assert!(sdl.contains("\"\"\"A user\"\"\"\ntype User {"));
        assert!(sdl.contains("  USER @deprecated(reason: \"use ADMIN\")"));
        assert!(sdl.contains("input NewUserInput {\n  name: String!\n  role: Role\n}"));
        assert!(!sdl.contains("__Type") && !sdl.contains("scalar String"));
        assert!(Schema::parse_and_validate(sdl, "s.graphql").is_ok());
    }

    #[test]
    fn validates_documents_and_variables() {
        let s = sample_schema();
        let ok = validate(
            &s,
            "query U($id: ID!) { user(id: $id) { id name friends(first: 2) { name } } }",
            Path::new("q.graphql"),
            Some(&json!({"id": "1"})),
        )
        .unwrap();
        assert!(ok.is_empty(), "{ok:?}");
        let bad = validate(
            &s,
            "query U($id: ID!) {\n  user(id: $id) { id nmae }\n}",
            Path::new("q.graphql"),
            Some(&json!({})),
        )
        .unwrap();
        let msgs: Vec<String> = bad
            .iter()
            .map(|d| format!("{}:{} {}", d.line, d.column, d.message))
            .collect();
        assert!(
            msgs.iter()
                .any(|m| m.starts_with("2:") && m.contains("nmae")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("required variable `$id: ID!` is missing")),
            "{msgs:?}"
        );
        assert!(
            !validate(&s, "{ user { id } }", Path::new("q"), None)
                .unwrap()
                .is_empty(),
            "missing required argument"
        );
        assert!(
            !validate(&s, "{ user(id: 1) { id ", Path::new("q"), None)
                .unwrap()
                .is_empty(),
            "syntax errors are reported"
        );
    }

    #[test]
    fn completes_fields_at_cursor() {
        let s = sample_schema();
        let names = |doc: &str, line, col| {
            complete_at(&s, doc, line, col)
                .into_iter()
                .map(|f| f.name)
                .collect::<Vec<_>>()
        };
        let doc = "query U($id: ID!) {\n  user(id: $id) {\n    na\n  }\n}\n";
        assert_eq!(names(doc, 3, 7), vec!["name"]);
        assert_eq!(
            names(doc, 3, 5),
            vec!["id", "name", "role", "friends", "__typename"]
        );
        assert_eq!(names("{ use", 1, 6), vec!["user", "users"]);
        assert_eq!(
            names("{ user(id: 1) { friends(first: 1) { ", 1, 37),
            vec!["id", "name", "role", "friends", "__typename"]
        );
        assert_eq!(names("mutation { cr", 1, 14), vec!["createUser"]);
        assert_eq!(names("fragment F on User { ro", 1, 24), vec!["role"]);
        assert!(names("query", 1, 6).is_empty());
    }

    #[test]
    fn generates_operations() {
        let s = sample_schema();
        let g = generate(&s, "Query.user").unwrap();
        assert_eq!(
            g.document,
            "query User($id: ID!) {\n  user(id: $id) {\n    id\n    name\n    role\n  }\n}\n"
        );
        assert_eq!(g.variables, json!({"id": "1"}));
        assert!(
            validate(&s, &g.document, Path::new("g"), Some(&g.variables))
                .unwrap()
                .is_empty()
        );
        let m = generate(&s, "Mutation.createUser").unwrap();
        assert!(m.document.starts_with(
            "mutation CreateUser($input: NewUserInput!) {\n  createUser(input: $input) {"
        ));
        assert_eq!(
            m.variables,
            json!({"input": {"name": "string", "role": "ADMIN"}})
        );
        assert!(generate(&s, "Query.nope").is_err());
        let mut renamed = s.clone();
        renamed["queryType"]["name"] = json!("QueryRoot");
        renamed["types"][0]["name"] = json!("QueryRoot");
        assert!(
            generate(&renamed, "Query.user")
                .unwrap()
                .document
                .starts_with("query User("),
            "Query is an alias for the root type"
        );
        assert!(generate(&s, "User.name").is_err());
    }

    #[test]
    fn detects_graphql_requests_and_endpoint() {
        let text = request_text(
            "Get user",
            "{{BASE_URL}}/graphql",
            Path::new("g/u.graphql"),
            Path::new("g/u.vars.json"),
            &[],
        );
        let spec = RequestSpec::from_config("g/u.curl".into(), crate::curlconf::parse(&text));
        assert_eq!(
            graphql_files(&spec),
            Some(GraphqlFiles {
                document: "g/u.graphql".into(),
                variables: Some("g/u.vars.json".into())
            })
        );
        let vars = BTreeMap::from([("BASE_URL".to_string(), "http://h".to_string())]);
        assert_eq!(endpoint(&spec, &vars).unwrap(), "http://h/graphql");
        assert!(text.contains("--expand-data \"{\\\"query\\\":\\\"{{GQL_QUERY:json}}\\\",\\\"variables\\\":{{GQL_VARS}}}\""), "{text}");
        assert!(
            text.contains("--variable GQL_QUERY@g/u.graphql\n"),
            "{text}"
        );
    }
}
