//! Shared fixtures for integration tests: a running test server and a
//! scratch copy of `examples/collection`.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Password the tests use for the demo login (the test server accepts any non-empty one).
pub const DEMO_PASSWORD: &str = "integration-pw-1234";

/// A test server plus a temporary copy of the example collection.
pub struct Fixture {
    /// Running test server.
    pub server: curly_testserver::Handle,
    /// Temp dir holding the collection copy and secret store.
    pub dir: tempfile::TempDir,
}

/// Recursively copies `from` into `to`, skipping `.curly/`.
pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == ".curly" {
            continue;
        }
        let (src, dst) = (entry.path(), to.join(&name));
        if src.is_dir() {
            copy_dir(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

impl Fixture {
    /// Starts a server on a random port and copies the collection.
    pub fn new() -> Fixture {
        let server = curly_testserver::spawn(0).expect("start test server");
        let dir = tempfile::tempdir().unwrap();
        copy_dir(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/collection"),
            &dir.path().join("collection"),
        );
        Fixture { server, dir }
    }

    /// Collection root.
    pub fn root(&self) -> PathBuf {
        self.dir.path().join("collection")
    }

    fn command(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.current_dir(self.root())
            .env("BASE_URL", self.server.base_url())
            .env("WS_URL", self.server.base_url().replace("http://", "ws://"))
            .env("GRPC_TARGET", self.server.grpc_addr.to_string())
            .env("DEMO_PASSWORD", DEMO_PASSWORD)
            .env(
                "CURLY_SECRET_STORE",
                format!("file:{}", self.dir.path().join("secrets.json").display()),
            )
            .env("OAUTH_CLIENT_SECRET", self.server.oauth_client_secret())
            .env("CURLY_NO_BROWSER", "1")
            .env_remove("API_TOKEN")
            .env_remove("ACCESS_TOKEN")
            .env_remove("CURLY_BROWSER")
            .env_remove("CURLY_CURL")
            .env("NO_COLOR", "1");
        c
    }

    /// Runs curly with `args`.
    pub fn curly(&self, args: &[&str]) -> Output {
        self.curly_env(args, &[])
    }

    /// Runs curly with `args` and extra environment variables.
    pub fn curly_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.command(env!("CARGO_BIN_EXE_curly"))
            .args(args)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    /// Logs in to `oauth/browser` with curl standing in for the browser.
    pub fn browser_login(&self, folder: &str) -> Output {
        self.curly_env(
            &["auth", "login", folder, "--timeout", "20"],
            &[("CURLY_BROWSER", "curl -s -L -o /dev/null")],
        )
    }

    /// Number of token requests the server has handled.
    pub fn token_requests(&self) -> u64 {
        let out = Command::new("curl")
            .args(["-s", &format!("{}/oauth/stats", self.server.base_url())])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["token_requests"].as_u64().unwrap()
    }

    /// Runs curly with `args`, feeding `stdin`.
    pub fn curly_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command(env!("CARGO_BIN_EXE_curly"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs plain curl with `args` from the collection root.
    pub fn curl(&self, args: &[&str]) -> Output {
        self.curl_env(args, &[])
    }

    /// Runs plain curl with `args` and extra environment variables.
    pub fn curl_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.command("curl")
            .args(args)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    /// Logs in through curly and returns the real token.
    pub fn login_token(&self) -> String {
        let out = self.curly(&[
            "run",
            "auth/login.curl",
            "--show-secrets",
            "--no-history",
            "--jq",
            ".access_token",
        ]);
        assert!(out.status.success(), "{}", stderr(&out));
        stdout(&out).trim().trim_matches('"').to_string()
    }
}

/// Stdout as a string.
pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Stderr as a string.
pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
