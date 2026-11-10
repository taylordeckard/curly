//! Every example request must run with plain `curl -K` and no curly.

mod common;

use common::{Fixture, stderr, stdout};

/// Runs plain curl from the collection root against `base_url`.
fn plain_curl(root: &std::path::Path, base_url: &str, args: &[&str]) -> std::process::Output {
    std::process::Command::new("curl")
        .args(args)
        .current_dir(root)
        .env("BASE_URL", base_url)
        .env("DEMO_PASSWORD", common::DEMO_PASSWORD)
        .output()
        .unwrap()
}

/// Each file runs against a fresh server so requests cannot affect each other.
#[test]
fn every_example_runs_with_plain_curl() {
    let fx = Fixture::new();
    let files = curly::curlconf::find_requests(&fx.root(), &fx.root()).unwrap();
    assert!(
        files.len() >= 20,
        "expected the full example collection, found {}",
        files.len()
    );
    for file in files
        .into_iter()
        .filter(|f| f.extension().is_some_and(|e| e == "curl"))
    {
        let rel = file.strip_prefix(fx.root()).unwrap().display().to_string();
        let server = curly_testserver::spawn(0).unwrap();
        let base = server.base_url();
        let login = plain_curl(
            &fx.root(),
            &base,
            &["-sS", "-K", "envs/local.curl", "-K", "auth/login.curl"],
        );
        let token: serde_json::Value = serde_json::from_slice(&login.stdout).unwrap();
        let token = token["access_token"].as_str().unwrap().to_string();
        let out = plain_curl(
            &fx.root(),
            &base,
            &[
                "-sS",
                "-K",
                "envs/local.curl",
                "--variable",
                &format!("API_TOKEN={token}"),
                "--variable",
                &format!("BEARER_AUTH_TOKEN={token}"),
                "--variable",
                &format!("ACCESS_TOKEN={token}"),
                "-K",
                &rel,
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
            ],
        );
        assert!(
            out.status.success(),
            "plain curl failed for {rel}: {}",
            stderr(&out)
        );
        let code: u16 = stdout(&out).trim().parse().unwrap();
        let expected = if rel.contains("missing") { 404 } else { 200 };
        let ok = if expected == 200 {
            (200..300).contains(&code)
        } else {
            code == expected
        };
        assert!(ok, "{rel}: plain curl got HTTP {code}");
    }
}

#[test]
fn curly_cmd_output_is_a_working_plain_curl_command() {
    let fx = Fixture::new();
    let out = fx.curly(&["cmd", "users/get-user.curl", "--var", "user_id=2"]);
    let text = stdout(&out);
    let cmd_line = text.lines().last().unwrap();
    assert_eq!(
        cmd_line,
        "curl --variable 'expected_name=Ada Lovelace' -K envs/local.curl --variable user_id=2 -K users/get-user.curl"
    );
    let out = std::process::Command::new("sh")
        .args(["-c", &format!("{cmd_line} -sS")])
        .current_dir(fx.root())
        .env("BASE_URL", fx.server.base_url())
        .output()
        .unwrap();
    assert!(stdout(&out).contains("Alan Turing"), "{}", stdout(&out));
}
