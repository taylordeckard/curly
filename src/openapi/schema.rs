//! Example values from schemas, and conversion of OpenAPI/Swagger schemas
//! into standalone JSON Schema (draft 2020-12) files.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::model::Spec;
use crate::vars::SecretNames;

/// Placeholder written instead of secret-looking example values.
pub const PLACEHOLDER: &str = "REPLACE_ME";

/// Maximum nesting depth when generating examples.
const MAX_DEPTH: usize = 8;

/// Whether an example is for a request (skip `readOnly`) or a response (skip `writeOnly`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Request body.
    Request,
    /// Response body.
    Response,
}

/// Builds example values from schemas.
pub struct Examples<'a> {
    spec: &'a Spec,
    secrets: &'a SecretNames,
}

impl<'a> Examples<'a> {
    /// Creates a generator for `spec`; property names matching `secrets` get a placeholder.
    pub fn new(spec: &'a Spec, secrets: &'a SecretNames) -> Self {
        Examples { spec, secrets }
    }

    /// Example for `schema`, preferring explicit examples, defaults, and enums.
    pub fn example(&self, schema: &Value, dir: Direction) -> Value {
        let mut stack = Vec::new();
        let v = self.build(schema, dir, 0, &mut stack);
        self.scrub(v)
    }

    /// Replaces values of secret-looking keys with [`PLACEHOLDER`].
    pub fn scrub(&self, v: Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.into_iter()
                    .map(|(k, v)| {
                        let v = if self.secrets.is_secret(&k) && (v.is_string() || v.is_number()) {
                            Value::String(PLACEHOLDER.into())
                        } else {
                            self.scrub(v)
                        };
                        (k, v)
                    })
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.into_iter().map(|v| self.scrub(v)).collect()),
            other => other,
        }
    }

    fn build(
        &self,
        schema: &Value,
        dir: Direction,
        depth: usize,
        stack: &mut Vec<String>,
    ) -> Value {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            if stack.iter().any(|s| s == r) || depth > MAX_DEPTH {
                return Value::Null;
            }
            let Some(target) = self.spec.pointer(r) else {
                return json!({});
            };
            stack.push(r.to_string());
            let v = self.build(target, dir, depth + 1, stack);
            stack.pop();
            return v;
        }
        if schema.get("format").and_then(Value::as_str) == Some("password") {
            return Value::String(PLACEHOLDER.into());
        }
        if let Some(e) = schema.get("example").or_else(|| schema.get("x-example")) {
            return e.clone();
        }
        if let Some(e) = schema
            .get("examples")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            return e.clone();
        }
        for key in ["default", "const"] {
            if let Some(v) = schema.get(key) {
                return v.clone();
            }
        }
        if let Some(first) = schema
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|v| !v.is_null()))
        {
            return first.clone();
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            let mut merged = Map::new();
            for s in all {
                if let Value::Object(m) = self.build(s, dir, depth + 1, stack) {
                    merged.extend(m);
                }
            }
            return Value::Object(merged);
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(first) = schema.get(key).and_then(Value::as_array).and_then(|a| {
                a.iter()
                    .find(|s| s.get("type").and_then(Value::as_str) != Some("null"))
            }) {
                return self.build(first, dir, depth + 1, stack);
            }
        }
        let ty = match schema.get("type") {
            Some(Value::String(t)) => t.clone(),
            Some(Value::Array(ts)) => ts
                .iter()
                .filter_map(Value::as_str)
                .find(|t| *t != "null")
                .unwrap_or("null")
                .to_string(),
            _ if schema.get("properties").is_some() => "object".into(),
            _ if schema.get("items").is_some() => "array".into(),
            _ => String::new(),
        };
        match ty.as_str() {
            "object" => {
                let mut out = Map::new();
                if depth <= MAX_DEPTH {
                    for (name, prop) in schema
                        .get("properties")
                        .and_then(Value::as_object)
                        .into_iter()
                        .flatten()
                    {
                        let resolved = self.spec.resolve(prop);
                        let skip = match dir {
                            Direction::Request => resolved
                                .get("readOnly")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            Direction::Response => resolved
                                .get("writeOnly")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        };
                        if !skip {
                            out.insert(name.clone(), self.build(prop, dir, depth + 1, stack));
                        }
                    }
                }
                Value::Object(out)
            }
            "array" => match schema.get("items") {
                Some(items) if depth <= MAX_DEPTH => {
                    let item = self.build(items, dir, depth + 1, stack);
                    if item.is_null() {
                        json!([])
                    } else {
                        json!([item])
                    }
                }
                _ => json!([]),
            },
            "string" => Value::String(
                match schema
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                {
                    "date-time" => "2024-01-01T00:00:00Z",
                    "date" => "2024-01-01",
                    "time" => "12:00:00",
                    "email" => "user@example.com",
                    "uuid" => "00000000-0000-4000-8000-000000000000",
                    "uri" | "url" => "https://example.com",
                    "hostname" => "example.com",
                    "ipv4" => "192.0.2.1",
                    "ipv6" => "2001:db8::1",
                    "byte" => "aGVsbG8=",
                    _ => "string",
                }
                .to_string(),
            ),
            "integer" => schema
                .get("minimum")
                .cloned()
                .filter(Value::is_number)
                .unwrap_or(json!(1)),
            "number" => schema
                .get("minimum")
                .cloned()
                .filter(Value::is_number)
                .unwrap_or(json!(1.5)),
            "boolean" => json!(true),
            "null" => Value::Null,
            _ => json!({}),
        }
    }
}

/// Keys whose values are data, not subschemas, and are copied unchanged.
const DATA_KEYS: &[&str] = &["enum", "const", "default", "required"];
/// OpenAPI-only keywords removed from converted schemas.
const DROP_KEYS: &[&str] = &[
    "discriminator",
    "xml",
    "externalDocs",
    "example",
    "examples",
    "nullable",
    "x-nullable",
];

/// Converts OpenAPI schemas to JSON Schema, collecting referenced component schemas into `$defs`.
pub struct Converter<'a> {
    spec: &'a Spec,
    defs: BTreeMap<String, Value>,
}

/// Component name for refs into `#/components/schemas/` or `#/definitions/`.
fn component_name(r: &str) -> Option<&str> {
    r.strip_prefix("#/components/schemas/")
        .or_else(|| r.strip_prefix("#/definitions/"))
}

impl<'a> Converter<'a> {
    /// Creates a converter.
    pub fn new(spec: &'a Spec) -> Self {
        Converter {
            spec,
            defs: BTreeMap::new(),
        }
    }

    /// Converts `schema` into a standalone JSON Schema document.
    pub fn document(mut self, schema: &Value) -> Value {
        let root = self.convert(schema, 0);
        let mut doc = Map::new();
        doc.insert(
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        );
        match root {
            Value::Object(m) => doc.extend(m),
            other => {
                doc.insert("allOf".into(), json!([other]));
            }
        }
        if !self.defs.is_empty() {
            doc.insert(
                "$defs".into(),
                Value::Object(self.defs.into_iter().collect()),
            );
        }
        Value::Object(doc)
    }

    fn convert(&mut self, v: &Value, depth: usize) -> Value {
        if depth > 64 {
            return json!({});
        }
        match v {
            Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(Value::as_str) {
                    if let Some(name) = component_name(r) {
                        let key = name.replace("~1", "/").replace("~0", "~");
                        if !self.defs.contains_key(&key) {
                            self.defs.insert(key.clone(), json!({}));
                            let target = self.spec.pointer(r).cloned().unwrap_or(json!({}));
                            let converted = self.convert(&target, depth + 1);
                            self.defs.insert(key.clone(), converted);
                        }
                        return json!({ "$ref": format!("#/$defs/{}", key.replace('~', "~0").replace('/', "~1")) });
                    }
                    let target = self.spec.pointer(r).cloned().unwrap_or(json!({}));
                    return self.convert(&target, depth + 1);
                }
                if m.get("type").and_then(Value::as_str) == Some("file") {
                    return json!({});
                }
                let mut out = Map::new();
                for (k, val) in m {
                    if DROP_KEYS.contains(&k.as_str()) || k.starts_with("x-") {
                        continue;
                    }
                    let converted = if DATA_KEYS.contains(&k.as_str()) {
                        val.clone()
                    } else {
                        self.convert(val, depth + 1)
                    };
                    out.insert(k.clone(), converted);
                }
                for (bound, exclusive) in [
                    ("minimum", "exclusiveMinimum"),
                    ("maximum", "exclusiveMaximum"),
                ] {
                    if out.get(exclusive) == Some(&json!(true)) {
                        if let Some(b) = out.remove(bound) {
                            out.insert(exclusive.into(), b);
                        }
                    } else if out.get(exclusive) == Some(&json!(false)) {
                        out.remove(exclusive);
                    }
                }
                let nullable = [m.get("nullable"), m.get("x-nullable")]
                    .into_iter()
                    .flatten()
                    .any(|n| n == &json!(true));
                if nullable {
                    match out.get("type").cloned() {
                        Some(Value::String(t)) => {
                            out.insert("type".into(), json!([t, "null"]));
                            if let Some(Value::Array(e)) = out.get_mut("enum")
                                && !e.contains(&Value::Null)
                            {
                                e.push(Value::Null);
                            }
                        }
                        _ => return json!({ "anyOf": [Value::Object(out), {"type": "null"}] }),
                    }
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| self.convert(x, depth + 1)).collect()),
            other => other.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r##"
openapi: 3.0.3
info: {title: t, version: "1"}
paths: {}
components:
  schemas:
    Pet:
      allOf:
        - $ref: "#/components/schemas/Base"
        - type: object
          required: [name]
          properties:
            name: {type: string, example: Rex}
            tag: {type: string, nullable: true}
            status: {type: string, enum: [available, sold]}
            born: {type: string, format: date}
            parent: {$ref: "#/components/schemas/Pet"}
            weight: {type: number, minimum: 0, exclusiveMinimum: true}
    Base:
      type: object
      properties:
        id: {type: integer, readOnly: true, format: int64}
        api_key: {type: string, example: abc123}
        secret_note: {type: string, writeOnly: true}
"##;

    fn spec() -> Spec {
        Spec::parse(SPEC).unwrap()
    }

    #[test]
    fn examples_respect_direction_secrets_and_cycles() {
        let spec = spec();
        let names = SecretNames::new(&[]).unwrap();
        let ex = Examples::new(&spec, &names);
        let pet = json!({"$ref": "#/components/schemas/Pet"});
        let req = ex.example(&pet, Direction::Request);
        assert_eq!(req["name"], "Rex");
        assert_eq!(req["status"], "available");
        assert_eq!(req["born"], "2024-01-01");
        assert_eq!(
            req["api_key"], PLACEHOLDER,
            "spec example for a secret-looking key is not copied"
        );
        assert!(req.get("id").is_none(), "readOnly skipped in requests");
        assert!(req["parent"].is_null(), "recursive ref stops");
        assert_eq!(req["weight"], 0);
        let resp = ex.example(&pet, Direction::Response);
        assert_eq!(resp["id"], 1);
        assert!(
            resp.get("secret_note").is_none(),
            "writeOnly skipped in responses"
        );
        let pw = ex.example(&json!({"type": "object", "properties": {"password": {"type": "string", "format": "password"}}}), Direction::Request);
        assert_eq!(pw["password"], PLACEHOLDER);
        assert_eq!(
            ex.example(&json!({"type": ["integer", "null"]}), Direction::Request),
            json!(1)
        );
        assert_eq!(
            ex.example(
                &json!({"type": "array", "items": {"type": "string", "format": "uuid"}}),
                Direction::Request
            )
            .as_array()
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn converts_to_validating_json_schema() {
        let spec = spec();
        let doc = Converter::new(&spec).document(&json!({"$ref": "#/components/schemas/Pet"}));
        assert_eq!(doc["$ref"], "#/$defs/Pet");
        let pet = &doc["$defs"]["Pet"]["allOf"][1]["properties"];
        assert_eq!(pet["tag"]["type"], json!(["string", "null"]));
        assert_eq!(pet["parent"]["$ref"], "#/$defs/Pet");
        assert_eq!(pet["weight"]["exclusiveMinimum"], 0);
        assert!(pet["weight"].get("minimum").is_none());
        assert!(pet["name"].get("example").is_none());
        assert!(doc["$defs"].get("Base").is_some());
        let validator = jsonschema::validator_for(&doc).expect("valid JSON Schema");
        assert!(validator.is_valid(&json!({"id": 1, "name": "Rex", "tag": null, "weight": 2})));
        assert!(
            !validator.is_valid(&json!({"tag": "x"})),
            "name is required"
        );
        assert!(
            !validator.is_valid(&json!({"name": "Rex", "weight": 0})),
            "exclusive minimum"
        );
        assert!(
            !validator.is_valid(&json!({"name": "Rex", "parent": {"tag": 5}})),
            "recursive validation"
        );
    }
}
