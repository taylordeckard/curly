//! Writing requests the way curl is used on the command line: `curly new`
//! from a curl command, `curly curl` for ad-hoc calls, and `curly fmt`.

mod common;

use std::fs;
use std::process::Command;

use common::{Fixture, stderr, stdout};

fn file_text(fx: &Fixture, rel: &str) -> String {
    fs::read_to_string(fx.root().join(rel)).unwrap()
}

#[test]
fn new_from_a_command_templates_host_and_credentials() {
    let fx = Fixture::new();
    let token = fx.login_token();
    let out = fx.curly(&[
        "new",
        "users/me-pasted.curl",
        "--",
        "curl",
        "-sS",
        "-H",
        &format!("Authorization: Bearer {token}"),
        &format!("{}/me", fx.server.base_url()),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("stored secrets: BEARER_TOKEN")
            && err.contains("dropped output-only options")
            && err.contains("--silent --show-error"),
        "{err}"
    );
    let text = file_text(&fx, "users/me-pasted.curl");
    assert_eq!(
        text,
        "# @name me-pasted\n--expand-url {{BASE_URL}}/me\n--expand-header \"Authorization: Bearer {{BEARER_TOKEN}}\"\n",
        "the collection's BASE_URL is reused"
    );
    assert!(
        !text.contains(&token) && !file_text(&fx, "envs/local.curl").contains(&token),
        "token never reaches files"
    );
    assert!(file_text(&fx, "envs/local.curl").contains("--variable %BEARER_TOKEN="));
    assert!(fx.curly(&["lint", "users/me-pasted.curl"]).status.success());
    let run = fx.curly(&["run", "users/me-pasted.curl", "--jq", ".username"]);
    assert_eq!(
        stdout(&run).trim(),
        "\"demo\"",
        "the stored token is used: {}",
        stderr(&run)
    );
    let plain = fx.curl(&[
        "-sS",
        "-K",
        "envs/local.curl",
        "--variable",
        &format!("BEARER_TOKEN={token}"),
        "-K",
        "users/me-pasted.curl",
    ]);
    assert!(
        stdout(&plain).contains("\"username\":\"demo\""),
        "the new file runs with plain curl"
    );
    let again = fx.curly(&["new", "users/me-pasted.curl", "--", "curl", "https://x/y"]);
    assert_eq!(again.status.code(), Some(2), "no silent overwrite");
}

#[test]
fn new_reads_browser_style_commands_from_stdin() {
    let fx = Fixture::new();
    let pasted = format!(
        "curl '{}/login' \\\n  -H 'content-type: application/json' \\\n  -H 'accept: */*' \\\n  --data-raw $'{{\"username\":\"demo\",\"password\":\"it\\'s secret\"}}' \\\n  --compressed\n",
        fx.server.base_url()
    );
    let out = fx.curly_stdin(
        &[
            "new",
            "auth/pasted-login.curl",
            "--stdin",
            "--name",
            "Pasted login",
        ],
        &pasted,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let text = file_text(&fx, "auth/pasted-login.curl");
    assert!(
        text.starts_with("# @name Pasted login\n--expand-url {{BASE_URL}}/login\n"),
        "{text}"
    );
    assert!(text.contains("--expand-data-raw \"{\\\"username\\\":\\\"demo\\\",\\\"password\\\":\\\"{{PASSWORD:json}}\\\"}\"") && text.contains("--compressed"), "{text}");
    assert!(!text.contains("it's secret"));
    let run = fx.curly(&["run", "auth/pasted-login.curl", "--jq", ".token_type"]);
    assert_eq!(stdout(&run).trim(), "\"Bearer\"", "{}", stderr(&run));
    let literal = fx.curly(&[
        "new",
        "auth/literal.curl",
        "--literal",
        "--no-store-secrets",
        "--",
        "curl -H 'X-Api-Key: k1' https://api.test/x",
    ]);
    assert!(literal.status.success(), "{}", stderr(&literal));
    assert_eq!(
        file_text(&fx, "auth/literal.curl"),
        "# @name literal\n--url https://api.test/x\n--header \"X-Api-Key: k1\"\n"
    );
    let lint = stdout(&fx.curly(&["lint", "auth/literal.curl"]));
    assert!(
        lint.contains("hardcoded credential"),
        "lint still flags literal credentials: {lint}"
    );
}

#[test]
fn curl_runs_ad_hoc_commands_with_the_viewer() {
    let fx = Fixture::new();
    let url = format!("{}/users/1", fx.server.base_url());
    let out = fx.curly(&[
        "curl",
        "-sS",
        "-H",
        "Authorization: Bearer abc123secret",
        &url,
        "-v",
        "--plain",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("> Authorization: Bearer [REDACTED]")
            && s.contains("HTTP/1.1 200 OK")
            && s.contains("Ada Lovelace"),
        "{s}"
    );
    assert!(!s.contains("abc123secret"));
    assert_eq!(
        stdout(&fx.curly(&["curl", &url, "--jq", ".name"])).trim(),
        "\"Ada Lovelace\"",
        "curly flags work anywhere"
    );
    assert_eq!(
        stdout(&fx.curly(&["curl", "--raw", &url])),
        "{\"id\":1,\"name\":\"Ada Lovelace\",\"email\":\"ada@example.test\"}"
    );
    let range = stdout(&fx.curly(&["curl", "-r", "0-9", &url, "-v", "--plain"]));
    assert!(
        range.contains("> Range: bytes=0-9"),
        "-r stays curl's --range in `curly curl`: {range}"
    );
    let hist = stdout(&fx.curly(&["history", "list"]));
    assert!(
        hist.contains(&url),
        "ad-hoc calls are recorded by URL: {hist}"
    );

    let outside = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_curly"))
        .args(["curl", "--body", &url])
        .current_dir(outside.path())
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("\"name\": \"Ada Lovelace\""));
    assert!(
        !outside.path().join(".curly").exists(),
        "outside a collection nothing is written"
    );
    let bad = fx.curly(&["curl", "--bogus-flag", &url]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(
        stderr(&bad).contains("unknown curl option `--bogus-flag`"),
        "{}",
        stderr(&bad)
    );
}

#[test]
fn curl_save_writes_a_request_file_and_runs_it() {
    let fx = Fixture::new();
    let out = fx.curly(&[
        "curl",
        "--save",
        "misc/echo-key.curl",
        "-X",
        "POST",
        &format!("{}/echo", fx.server.base_url()),
        "-H",
        "X-Api-Key: k-12345",
        "-d",
        "x=1",
        "--body",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("\"x-api-key\": \"[REDACTED:X_API_KEY]\""),
        "the saved file ran with the stored key: {}",
        stdout(&out)
    );
    assert_eq!(
        file_text(&fx, "misc/echo-key.curl"),
        "# @name echo-key\n--expand-url {{BASE_URL}}/echo\n--request POST\n--expand-header \"X-Api-Key: {{X_API_KEY}}\"\n--data x=1\n"
    );
    let hist = stdout(&fx.curly(&["history", "list"]));
    assert!(
        hist.contains("misc/echo-key.curl"),
        "history links to the saved file: {hist}"
    );
}

#[test]
fn fmt_rewrites_config_style_into_flag_style() {
    let fx = Fixture::new();
    let check = fx.curly(&["fmt", "--check"]);
    assert_eq!(
        check.status.code(),
        Some(0),
        "the examples are already in flag style: {}",
        stdout(&check)
    );
    fs::write(fx.root().join("misc/old.curl"), "# @name Old style\nexpand-url = \"{{BASE_URL}}/health\"\nheader = \"Accept: application/json\"\nlocation\n").unwrap();
    let check = fx.curly(&["fmt", "--check"]);
    assert_eq!(check.status.code(), Some(1));
    assert!(stdout(&check).contains("would reformat misc/old.curl"));
    assert!(fx.curly(&["fmt", "misc"]).status.success());
    assert_eq!(
        file_text(&fx, "misc/old.curl"),
        "# @name Old style\n--expand-url {{BASE_URL}}/health\n--header \"Accept: application/json\"\n--location\n"
    );
    assert!(fx.curly(&["run", "misc/old.curl"]).status.success());
}
