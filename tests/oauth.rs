//! End-to-end tests for OAuth 2.0: client credentials, authorization code with
//! PKCE through a loopback redirect, caching, refresh, and redaction.

mod common;

use std::fs;

use common::{Fixture, stderr, stdout};

/// Everything under `.curly/` as lossy text.
fn state_text(fx: &Fixture) -> String {
    let mut out = String::new();
    for entry in fs::read_dir(fx.root().join(".curly")).unwrap() {
        if let Ok(b) = fs::read(entry.unwrap().path()) {
            out.push_str(&String::from_utf8_lossy(&b));
        }
    }
    out
}

#[test]
fn client_credentials_fetches_once_and_caches() {
    let fx = Fixture::new();
    for _ in 0..2 {
        let out = fx.curly(&["run", "oauth/service-me.curl", "-v"]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stdout(&out).contains("> Authorization: Bearer [REDACTED]"),
            "{}",
            stdout(&out)
        );
    }
    assert_eq!(fx.token_requests(), 1, "second run uses the cached token");

    let status = stdout(&fx.curly(&["auth", "status"]));
    assert!(status.contains("oauth  env=local  client_credentials  client=curly-service  scopes=users:read  expires in"), "{status}");
    assert!(status.contains("not refreshable"));

    let token = stdout(&fx.curly(&["auth", "token", "oauth"]))
        .trim()
        .to_string();
    assert_eq!(token.len(), 64);
    let plain = fx.curl(&[
        "-sS",
        "-K",
        "envs/local.curl",
        "--variable",
        &format!("ACCESS_TOKEN={token}"),
        "-K",
        "oauth/service-me.curl",
    ]);
    assert!(
        stdout(&plain).contains("\"username\":\"demo\""),
        "the token works with plain curl"
    );

    let state = state_text(&fx);
    assert!(
        !state.contains(&fx.server.oauth_client_secret()),
        "client secret never reaches .curly/"
    );
    assert!(
        !state.contains(&token),
        "access token never reaches history or the index"
    );
    let history = stdout(&fx.curly(&["history", "show", "1", "-v"]));
    assert!(
        history.contains("> POST ")
            && history.contains("/oauth/token")
            && history.contains("Authorization: Basic [REDACTED]"),
        "{history}"
    );
    assert!(
        history.contains("\"access_token\": \"[REDACTED]\""),
        "{history}"
    );

    assert_eq!(
        stdout(&fx.curly(&["auth", "logout", "--all"])).trim(),
        "removed 1 cached token"
    );
    assert_eq!(
        stdout(&fx.curly(&["auth", "status"])).trim(),
        "no cached tokens"
    );
    fx.curly(&["run", "oauth/service-me.curl"]);
    assert_eq!(fx.token_requests(), 2);
}

#[test]
fn bad_client_secret_fails_without_leaking_it() {
    let fx = Fixture::new();
    let wrong = "wrong-secret-value-123";
    let out = fx.curly_env(
        &["run", "oauth/service-me.curl"],
        &[("OAUTH_CLIENT_SECRET", wrong)],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = stderr(&out);
    assert!(
        err.contains("token endpoint returned 401: invalid_client bad client credentials"),
        "{err}"
    );
    assert!(!err.contains(wrong) && !state_text(&fx).contains(wrong));
}

#[test]
fn authorization_code_with_pkce_via_loopback_redirect() {
    let fx = Fixture::new();
    let before = fx.curly(&["run", "oauth/browser/me.curl"]);
    assert_eq!(before.status.code(), Some(2));
    assert!(
        stderr(&before).contains(
            "no valid OAuth token for oauth/browser; run `curly auth login oauth/browser -e local`"
        ),
        "{}",
        stderr(&before)
    );

    let login = fx.browser_login("oauth/browser");
    assert!(login.status.success(), "{}", stderr(&login));
    let err = stderr(&login);
    assert!(
        err.contains("code_challenge_method=S256")
            && err.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A"),
        "{err}"
    );
    assert!(
        err.contains("Logged in: oauth/browser (authorization_code, expires in"),
        "{err}"
    );
    assert!(err.contains("refreshable"));

    let run = fx.curly(&["run", "oauth/browser/me.curl"]);
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    assert_eq!(fx.token_requests(), 1);
    let cmd = stdout(&fx.curly(&["cmd", "oauth/browser/me.curl"]));
    assert!(
        cmd.contains("export ACCESS_TOKEN=\"$(curly auth token oauth/browser -e local)\""),
        "{cmd}"
    );
}

#[test]
fn expired_tokens_refresh_automatically() {
    let fx = Fixture::new();
    let cfg = fx.root().join("oauth/browser/_folder.toml");
    let text = fs::read_to_string(&cfg).unwrap() + "\n[auth.params]\ntest_expires_in = \"1\"\n";
    fs::write(&cfg, text).unwrap();
    assert!(fx.browser_login("oauth/browser").status.success());
    assert_eq!(fx.token_requests(), 1);
    for expected in [2, 3] {
        let run = fx.curly(&["run", "oauth/browser/me.curl"]);
        assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
        assert_eq!(
            fx.token_requests(),
            expected,
            "each run refreshes the short-lived token"
        );
    }
    assert!(stdout(&fx.curly(&["auth", "status"])).contains("refreshable"));
}

#[test]
fn failed_browser_command_stops_login_quickly() {
    let fx = Fixture::new();
    let start = std::time::Instant::now();
    let out = fx.curly_env(
        &["auth", "login", "oauth/browser", "--timeout", "60"],
        &[("CURLY_BROWSER", "false")],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("the browser command exited"),
        "{}",
        stderr(&out)
    );
    assert!(start.elapsed().as_secs() < 10);
}

#[test]
fn var_override_skips_oauth_and_none_stops_inheritance() {
    let fx = Fixture::new();
    let token = fx.login_token();
    let out = fx.curly(&[
        "run",
        "oauth/service-me.curl",
        "--var",
        &format!("ACCESS_TOKEN={token}"),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        fx.token_requests(),
        0,
        "an explicit --var wins and no token is fetched"
    );

    let dir = fx.root().join("oauth/public");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("_folder.toml"), "[auth]\ntype = \"none\"\n").unwrap();
    fs::write(
        dir.join("health.curl"),
        "expand-url = \"{{BASE_URL}}/health\"\n",
    )
    .unwrap();
    let out = fx.curly(&["run", "oauth/public/health.curl"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        fx.token_requests(),
        0,
        "type = none disables the inherited [auth]"
    );
    assert!(!stdout(&fx.curly(&["cmd", "oauth/public/health.curl"])).contains("curly auth token"));
}

#[test]
fn lint_checks_auth_config() {
    let fx = Fixture::new();
    let out = fx.curly(&["lint", "oauth"]);
    assert!(out.status.success(), "{}", stdout(&out));
    fs::write(
        fx.root().join("oauth/forgot.curl"),
        "expand-url = \"{{BASE_URL}}/me\"\n",
    )
    .unwrap();
    let cfg = fx.root().join("oauth/_folder.toml");
    let text = fs::read_to_string(&cfg)
        .unwrap()
        .replace("\"{{OAUTH_CLIENT_SECRET}}\"", "\"literal-secret\"");
    fs::write(&cfg, text).unwrap();
    let out = fx.curly(&["lint", "oauth"]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(
        s.contains("oauth/_folder.toml:0: error: hardcoded credential in [auth] client_secret"),
        "{s}"
    );
    assert!(s.contains("oauth/forgot.curl:0: warning: oauth/_folder.toml sets [auth], but this request never uses {{ACCESS_TOKEN}}"), "{s}");
}
