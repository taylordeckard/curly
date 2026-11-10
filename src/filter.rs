//! Response body filters: jq expressions (via jaq) and RFC 9535 JSONPath.

use anyhow::{Context, Result, anyhow, bail};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::Val;
use serde_json::Value;
use serde_json_path::JsonPath;

/// A filter over a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// jq program, e.g. `.items[] | .name`.
    Jq(String),
    /// JSONPath query, e.g. `$.items[*].name`.
    JsonPath(String),
}

impl Filter {
    /// Applies the filter to a JSON body, returning every output value.
    pub fn apply(&self, body: &[u8]) -> Result<Vec<Value>> {
        match self {
            Filter::Jq(program) => jq(program, body),
            Filter::JsonPath(path) => {
                let input: Value =
                    serde_json::from_slice(body).context("response body is not JSON")?;
                jsonpath(path, &input)
            }
        }
    }
}

/// Runs a JSONPath query against a value.
pub fn jsonpath(path: &str, input: &Value) -> Result<Vec<Value>> {
    let path = JsonPath::parse(path).map_err(|e| anyhow!("invalid JSONPath `{path}`: {e}"))?;
    Ok(path.query(input).all().into_iter().cloned().collect())
}

/// Runs a jq program against a JSON body.
pub fn jq(program: &str, body: &[u8]) -> Result<Vec<Value>> {
    let input = jaq_json::read::parse_single(body)
        .map_err(|e| anyhow!("response body is not JSON: {e}"))?;
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let modules = loader
        .load(
            &arena,
            File {
                code: program,
                path: (),
            },
        )
        .map_err(|_| anyhow!("invalid jq filter `{program}`"))?;
    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|_| anyhow!("invalid jq filter `{program}`"))?;
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let mut out = Vec::new();
    for v in filter.id.run((ctx, input)).map(unwrap_valr) {
        let v = v.map_err(|e| anyhow!("jq error: {e}"))?;
        out.push(serde_json::from_str(&v.to_string()).unwrap_or(Value::String(v.to_string())));
    }
    if out.len() > 100_000 {
        bail!("jq produced too many results");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BODY: &[u8] = br#"{"items":[{"name":"a","n":1},{"name":"b","n":2}],"total":2}"#;

    #[test]
    fn jq_filters() {
        assert_eq!(
            Filter::Jq(".items[].name".into()).apply(BODY).unwrap(),
            vec![json!("a"), json!("b")]
        );
        assert_eq!(
            Filter::Jq("[.items[].n] | add".into()).apply(BODY).unwrap(),
            vec![json!(3)]
        );
        assert_eq!(
            Filter::Jq(".items | length".into()).apply(BODY).unwrap(),
            vec![json!(2)]
        );
        assert!(Filter::Jq(".items[".into()).apply(BODY).is_err());
        assert!(Filter::Jq(".".into()).apply(b"not json").is_err());
    }

    #[test]
    fn jsonpath_filters() {
        assert_eq!(
            Filter::JsonPath("$.items[*].name".into())
                .apply(BODY)
                .unwrap(),
            vec![json!("a"), json!("b")]
        );
        assert_eq!(
            Filter::JsonPath("$.items[?@.n > 1].name".into())
                .apply(BODY)
                .unwrap(),
            vec![json!("b")]
        );
        assert!(Filter::JsonPath("$.items[".into()).apply(BODY).is_err());
    }
}
