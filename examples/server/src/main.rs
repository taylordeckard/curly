//! `curly-testserver [PORT]`: runs the example API on 127.0.0.1 (default port 8787).

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    curly_testserver::serve_forever(port).await
}
