//! End-to-end tests for `curly import openapi`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Fixture, stderr, stdout};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Runs curly in `dir` with a clean environment.
fn curly_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_curly"))
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env_remove("CURLY_CURL")
        .output()
        .unwrap()
}

/// Every file under `dir` as text, concatenated.
fn all_text(dir: &Path) -> String {
    let mut out = String::new();
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            out.push_str(&all_text(&p));
        } else if let Ok(t) = fs::read_to_string(&p) {
            out.push_str(&t);
        }
    }
    out
}

#[test]
fn import_from_url_then_lint_and_run_against_the_server() {
    let fx = Fixture::new();
    let url = format!("{}/openapi.yaml", fx.server.base_url());
    let out = fx.curly(&["import", "openapi", &url, "--out", "fresh"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("Imported 7 operations from curly test server into fresh/"),
        "{s}"
    );
    assert!(fx.root().join("fresh/openapi.yaml").is_file());
    assert_eq!(
        fs::read_to_string(fx.root().join("fresh/_folder.toml"))
            .unwrap()
            .lines()
            .last()
            .unwrap(),
        "order = [\"meta/\", \"users/\", \"auth/\"]"
    );
    let lint = fx.curly(&["lint", "fresh"]);
    assert!(lint.status.success(), "{}", stdout(&lint));
    let token = fx.login_token();
    let run = fx.curly(&[
        "run",
        "fresh",
        "--var",
        &format!("BEARER_AUTH_TOKEN={token}"),
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", stdout(&run));
    assert!(
        stdout(&run).contains("7 requests: 7 passed"),
        "{}",
        stdout(&run)
    );
    let body: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fx.root().join("fresh/auth/login.body.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        body,
        serde_json::json!({"username": "demo", "password": "REPLACE_ME"})
    );
}

#[test]
fn petstore_fixture_generates_expected_files() {
    let tmp = tempfile::tempdir().unwrap();
    let out = curly_in(
        tmp.path(),
        &[
            "import",
            "openapi",
            fixture("petstore-3.0.yaml").to_str().unwrap(),
            "--out",
            "pets",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("created a new collection"), "{s}");
    assert!(
        s.contains(
            "secrets to provide: PETSTORE_AUTH_TOKEN, API_KEY, BASIC_AUTH_PASSWORD, API_KEY_QUERY"
        ),
        "{s}"
    );
    assert!(
        s.contains("note: other server: http://localhost:4010 (Local mock)"),
        "{s}"
    );
    let root = tmp.path().join("pets");
    let read = |p: &str| fs::read_to_string(root.join(p)).unwrap();

    let list = read("pets/list-pets.curl");
    assert!(
        list.contains("--expand-url {{BASE_URL}}/pets?status={{status:url}}"),
        "{list}"
    );
    assert!(list.contains("--expand-header \"X-Request-ID: {{X_Request_ID}}\""));
    assert!(list.contains("--expand-header \"Authorization: Bearer {{PETSTORE_AUTH_TOKEN}}\""));
    assert!(list.contains("# Optional query parameters: limit"));
    assert!(read("pets/get-pet-by-id.curl").contains("# @deprecated true"));
    let delete = read("pets/delete-pet.curl");
    assert!(
        delete.contains("--request DELETE")
            && delete.contains("--expand-header \"X-API-Key: {{API_KEY}}\"")
            && delete.contains("# Other accepted auth: basicAuth"),
        "{delete}"
    );
    assert!(read("store/get-inventory.curl").contains("?key={{API_KEY_QUERY:url}}"));
    let order = read("store/post-store-order.curl");
    assert!(
        order.contains("--expand-user {{BASIC_AUTH_USER}}:{{BASIC_AUTH_PASSWORD}}")
            && order.contains("--data-urlencode petId=7"),
        "{order}"
    );
    assert!(read("default/get-ping.curl").contains("--header \"Accept: text/plain\""));

    let body: serde_json::Value = serde_json::from_str(&read("pets/add-pet.body.json")).unwrap();
    assert_eq!(
        body["name"], "Rex",
        "media-type examples win over schema examples"
    );
    let test = read("pets/get-pet-by-id.test.toml");
    assert!(
        test.contains("status = 200")
            && test.contains("schema = \"pets/get-pet-by-id.200.schema.json\""),
        "{test}"
    );
    let schema: serde_json::Value =
        serde_json::from_str(&read("pets/get-pet-by-id.200.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&serde_json::json!({"id": 1, "name": "doggie", "tag": null, "category": {"parent": {"name": "x"}}})));
    assert!(!validator.is_valid(&serde_json::json!({"name": "doggie", "status": "lost"})));

    let env = read("envs/local.curl");
    assert!(
        env.contains("--variable BASE_URL=https://eu.petstore.test/v2"),
        "server variables are substituted: {env}"
    );
    assert!(
        env.contains("--variable %PETSTORE_AUTH_TOKEN=")
            && env.contains(
                "# OAuth 2.0 authorizationCode flow: authorize https://auth.petstore.test/authorize"
            )
    );
    assert!(env.contains("--variable petId=42"));

    let everything = all_text(&root);
    let generated = everything.replace(
        &fs::read_to_string(fixture("petstore-3.0.yaml")).unwrap(),
        "",
    );
    assert!(
        !generated.contains("do-not-copy"),
        "secret-looking spec examples are replaced"
    );
    assert!(generated.contains("client_secret=REPLACE_ME"));
    let lint = curly_in(&root, &["lint"]);
    assert!(lint.status.success(), "{}", stdout(&lint));
}

#[test]
fn swagger2_fixture_generates_expected_files() {
    let tmp = tempfile::tempdir().unwrap();
    let out = curly_in(
        tmp.path(),
        &[
            "import",
            "swagger",
            fixture("swagger-2.0.json").to_str().unwrap(),
            "--out",
            "legacy",
            "-e",
            "staging",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let root = tmp.path().join("legacy");
    let read = |p: &str| fs::read_to_string(root.join(p)).unwrap();
    assert!(read("curly.toml").contains("default_env = \"staging\""));
    let env = read("envs/staging.curl");
    assert!(
        env.contains("BASE_URL=https://legacy.example.test:8443/api")
            && env.contains("--variable id=5")
            && env.contains("--variable %TOKEN="),
        "{env}"
    );
    assert!(
        read("users/get-user.curl").contains("--expand-user {{BASIC_USER}}:{{BASIC_PASSWORD}}")
    );
    let update = read("users/update-user.curl");
    assert!(
        update.contains("?access_token={{TOKEN:url}}")
            && update.contains("--json @users/update-user.body.json"),
        "{update}"
    );
    let session = read("auth/create-session.curl");
    assert!(
        session.contains("--data-urlencode username=admin")
            && session.contains("--data-urlencode password=REPLACE_ME"),
        "{session}"
    );
    assert!(
        !session.contains("optional"),
        "required formData makes the body required: {session}"
    );
    assert!(
        !session.contains("expand-user"),
        "`security: []` disables auth"
    );
    let schema: serde_json::Value =
        serde_json::from_str(&read("users/get-user.200.schema.json")).unwrap();
    assert_eq!(
        schema["$defs"]["User"]["properties"]["manager"]["$ref"],
        "#/$defs/User"
    );
    assert_eq!(
        schema["$defs"]["User"]["properties"]["nickname"]["type"],
        serde_json::json!(["string", "null"])
    );
    let lint = curly_in(&root, &["lint"]);
    assert!(lint.status.success(), "{}", stdout(&lint));
}

#[test]
fn reimport_keeps_edits_unless_forced() {
    let tmp = tempfile::tempdir().unwrap();
    let spec = fixture("swagger-2.0.json");
    let spec = spec.to_str().unwrap();
    curly_in(tmp.path(), &["import", "openapi", spec, "--out", "legacy"]);
    let file = tmp.path().join("legacy/users/get-user.curl");
    fs::write(&file, "# edited\nurl = x\n").unwrap();
    let again = curly_in(tmp.path(), &["import", "openapi", spec, "--out", "legacy"]);
    assert!(
        stdout(&again).contains("0 files written, 13 existing files kept"),
        "{}",
        stdout(&again)
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), "# edited\nurl = x\n");
    let env = fs::read_to_string(tmp.path().join("legacy/envs/local.curl")).unwrap();
    assert_eq!(
        env.matches("BASE_URL=").count(),
        1,
        "variables are not duplicated"
    );
    curly_in(
        tmp.path(),
        &["import", "openapi", spec, "--out", "legacy", "--force"],
    );
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("# @operation getUser")
    );
}

#[test]
fn bad_sources_fail_clearly() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("notes.yaml"), "hello: world\n").unwrap();
    let out = curly_in(tmp.path(), &["import", "openapi", "notes.yaml"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("not an OpenAPI 3.x or Swagger 2.0 document"),
        "{}",
        stderr(&out)
    );
    let out = curly_in(
        tmp.path(),
        &["import", "openapi", "http://127.0.0.1:9/openapi.json"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("downloading http://127.0.0.1:9/openapi.json failed"),
        "{}",
        stderr(&out)
    );
}
