//! End-to-end tests for `curly docs` (HTML and Markdown).

mod common;

use std::fs;

use common::{Fixture, stderr, stdout};

#[test]
fn html_and_markdown_cover_every_protocol_without_secrets() {
    let fx = Fixture::new();
    let stored = "stored-secret-value-9876";
    fx.curly_stdin(&["secret", "set", "MY_API_KEY"], &format!("{stored}\n"));
    fx.curly_stdin(&["secret", "set", "API_TOKEN"], "stored-api-token-5432\n");
    let out = fx.curly(&["docs"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("docs/index.html (34 requests in 13 folders)"),
        "{}",
        stdout(&out)
    );
    let md_out = fx.curly(&["docs", "--format", "md", "--out", "md"]);
    assert!(md_out.status.success(), "{}", stderr(&md_out));
    let html = fs::read_to_string(fx.root().join("docs/index.html")).unwrap();
    let md = fs::read_to_string(fx.root().join("md/index.md")).unwrap();

    for doc in [&html, &md] {
        for needle in [
            "Get user",
            "Fetches one user by id.",
            "users/get-user.curl",
            "body matches the JSON Schema schemas/user.json",
            "query User($id: ID!)",
            "receive within 2000 ms",
            "grpc://{{GRPC_TARGET}}/curly.test.v1.UserService/Shout",
            "OAuth 2.0 client_credentials",
            "users/get-missing-user.404.example.json",
        ] {
            let found = doc.contains(needle)
                || doc.contains(&needle.replace('"', "&quot;").replace('<', "&lt;"));
            assert!(found, "missing {needle:?}");
        }
        for secret in [
            common::DEMO_PASSWORD,
            stored,
            &fx.server.oauth_client_secret(),
        ] {
            assert!(!doc.contains(secret), "docs must not contain secret values");
        }
    }
    assert!(
        md.contains("export API_TOKEN=\"$(curly secret get API_TOKEN -e local)\"\ncurl -K envs/local.curl --variable %API_TOKEN -K auth/me.curl\n```"),
        "plain curl command shows how to supply stored secrets without their values"
    );
    assert!(
        md.contains("```sh\ncurl --variable 'expected_name=Ada Lovelace' -K envs/local.curl -K users/get-user.curl\n```"),
        "requests that do not use a stored secret do not export it"
    );
    assert!(
        md.contains("| `DEMO_PASSWORD` | *secret* |") && md.contains("| `MY_API_KEY` | *secret* |"),
        "secrets are named, not shown"
    );
    assert!(
        md.contains(&format!("| `BASE_URL` | `{}` |", fx.server.base_url())),
        "non-secret values are shown"
    );
    assert!(html.contains("<span class=\"secret\">secret</span>"));
    assert!(
        !html.contains("<script") && !html.contains("<link") && !html.contains("src="),
        "self-contained: no scripts or external assets"
    );
}

#[test]
fn html_is_well_formed_and_escapes_content() {
    let fx = Fixture::new();
    fs::write(fx.root().join("xss.curl"), "# @name <script>alert('x')</script>\n# @description a & b < c\nexpand-url = \"{{BASE_URL}}/health?a=<b>\"\n").unwrap();
    assert!(fx.curly(&["docs"]).status.success());
    let html = fs::read_to_string(fx.root().join("docs/index.html")).unwrap();
    assert!(
        html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")
            && !html.contains("<script>"),
        "names are escaped"
    );
    assert!(html.contains("a &amp; b &lt; c"));
    let mut reader = quick_xml::Reader::from_str(&html);
    reader.config_mut().check_end_names = true;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(e) => panic!(
                "HTML is not well-formed at {}: {e}",
                reader.buffer_position()
            ),
        }
    }
}

#[test]
fn subsets_and_deterministic_output() {
    let fx = Fixture::new();
    let out = fx.curly(&["docs", "users", "--format", "md", "--out", "out"]);
    assert!(
        stdout(&out).contains("(5 requests in 1 folders)"),
        "{}",
        stdout(&out)
    );
    let first = fs::read_to_string(fx.root().join("out/index.md")).unwrap();
    assert!(first.contains("## users/") && !first.contains("## graphql/"));
    fx.curly(&["docs", "users", "--format", "md", "--out", "out"]);
    assert_eq!(
        first,
        fs::read_to_string(fx.root().join("out/index.md")).unwrap(),
        "same input, same output"
    );
    assert_eq!(
        fx.curly(&["docs", "--format", "pdf"]).status.code(),
        Some(2)
    );
}
