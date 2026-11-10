//! End-to-end tests for `curly mock` (OpenAPI and saved examples) and
//! `curly history save`.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use common::{Fixture, stderr, stdout};

/// A running `curly mock`, killed on drop.
struct Mock {
    child: Child,
    base: String,
}

impl Mock {
    fn start(fx: &Fixture, args: &[&str]) -> Mock {
        let mut child = Command::new(env!("CARGO_BIN_EXE_curly"))
            .arg("mock")
            .args(args)
            .args(["--port", "0"])
            .current_dir(fx.root())
            .env(
                "CURLY_SECRET_STORE",
                format!("file:{}", fx.dir.path().join("secrets.json").display()),
            )
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let first = lines.next().unwrap().unwrap();
        let base = first
            .split_whitespace()
            .find(|w| w.starts_with("http://"))
            .unwrap_or_else(|| panic!("unexpected mock output: {first}"))
            .to_string();
        std::thread::spawn(move || for _ in lines {});
        Mock { child, base }
    }

    fn curl(&self, args: &[&str]) -> String {
        let out = Command::new("curl")
            .args(["-s"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn openapi_mock_serves_schema_valid_examples() {
    let fx = Fixture::new();
    let mock = Mock::start(&fx, &["--spec", "imported/openapi.yaml", "--validate"]);
    let run = fx.curly(&[
        "run",
        "imported",
        "--var",
        &format!("BASE_URL={}", mock.base),
        "--var",
        "BEARER_AUTH_TOKEN=x",
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", stdout(&run));
    assert!(
        stdout(&run).contains("7 requests: 7 passed"),
        "the imported tests and schemas pass against the mock: {}",
        stdout(&run)
    );

    let user: serde_json::Value =
        serde_json::from_str(&mock.curl(&[&format!("{}/users/1", mock.base)])).unwrap();
    assert_eq!(user["name"], "Grace Hopper");
    let not_found = mock.curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-H",
        "Prefer: code=404",
        &format!("{}/users/1", mock.base),
    ]);
    assert_eq!(not_found, "404");
    assert_eq!(
        mock.curl(&[
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{}/users/1?__code=404", mock.base)
        ]),
        "404"
    );
    let invalid = mock.curl(&[
        "-X",
        "POST",
        "--json",
        "{\"nam\":1}",
        &format!("{}/users", mock.base),
    ]);
    assert!(
        invalid.contains("request does not match the spec")
            && invalid.contains("\\\"name\\\" is a required property"),
        "{invalid}"
    );
    let wrong_method = mock.curl(&["-i", "-X", "PATCH", &format!("{}/users/1", mock.base)]);
    assert!(
        wrong_method.starts_with("HTTP/1.1 405") && wrong_method.contains("allow: DELETE, GET"),
        "{wrong_method}"
    );
    let unknown = mock.curl(&[&format!("{}/nope", mock.base)]);
    assert!(
        unknown.contains("no mock route for this path") && unknown.contains("GET /users/{userId}"),
        "{unknown}"
    );
}

#[test]
fn saved_examples_become_mock_routes() {
    let fx = Fixture::new();
    let token = fx.login_token();
    fx.curly(&["run", "auth/login.curl"]);
    let saved = fx.curly(&["history", "save", "last", "--force"]);
    assert!(
        stdout(&saved).contains("as auth/login.example.json (redacted)"),
        "{}",
        stdout(&saved)
    );
    fx.curly(&["run", "users/get-user.curl", "--var", "user_id=999"]);
    let saved = fx.curly(&["history", "save", "last"]);
    assert!(
        stdout(&saved).contains("as users/get-user.404.example.json"),
        "non-2xx responses get a status suffix: {}",
        stdout(&saved)
    );
    let again = fx.curly(&["history", "save", "last"]);
    assert_eq!(again.status.code(), Some(2));
    assert!(stderr(&again).contains("exists (use --force to overwrite)"));
    let example = std::fs::read_to_string(fx.root().join("auth/login.example.json")).unwrap();
    assert!(
        example.contains("\"access_token\": \"[REDACTED]\"") && !example.contains(&token[..16]),
        "{example}"
    );

    let mock = Mock::start(&fx, &[]);
    let user = mock.curl(&[&format!("{}/users/7", mock.base)]);
    assert!(
        user.contains("\"name\": \"Ada Lovelace\""),
        "default example: {user}"
    );
    let missing = mock.curl(&["-H", "Prefer: code=404", &format!("{}/users/7", mock.base)]);
    assert!(missing.contains("user not found"), "{missing}");
    let none = mock.curl(&["-H", "Prefer: code=418", &format!("{}/users/7", mock.base)]);
    assert!(
        none.contains("\"available\": [\n    200,\n    404\n  ]"),
        "{none}"
    );
    let run = fx.curly(&[
        "run",
        "users/get-user.curl",
        "users/get-missing-user.curl",
        "--var",
        &format!("BASE_URL={}", mock.base),
    ]);
    assert!(
        stdout(&run).contains("2 requests: 2 passed"),
        "{}",
        stdout(&run)
    );
}

#[test]
fn mock_refuses_non_loopback_and_empty_sources() {
    let fx = Fixture::new();
    let out = fx.curly(&[
        "mock",
        "--host",
        "0.0.0.0",
        "--spec",
        "imported/openapi.yaml",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("only binds to loopback addresses"),
        "{}",
        stderr(&out)
    );
    for f in walk(&fx.root()) {
        if f.to_string_lossy().ends_with(".example.json") {
            std::fs::remove_file(f).unwrap();
        }
    }
    let out = fx.curly(&["mock", "--port", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("nothing to mock"), "{}", stderr(&out));
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
