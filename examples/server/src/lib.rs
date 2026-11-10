//! Local test server for the curly example collection and integration tests.
//!
//! It binds to loopback only and keeps all state in memory. Tokens are random
//! per process; nothing here is a real credential.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::oneshot;

mod graphql;
pub mod grpc;
mod oauth;
mod ws;

/// OpenAPI description of this server, served at `/openapi.yaml`.
pub const OPENAPI_SPEC: &str = include_str!("../../openapi/testserver.yaml");

/// A user record served by the `/users` endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Server-assigned identifier.
    pub id: u64,
    /// Display name.
    pub name: String,
    /// Email address.
    pub email: String,
}

/// Payload accepted by `POST /users`.
#[derive(Debug, Deserialize)]
struct NewUser {
    name: String,
    email: String,
}

/// Payload accepted by `POST /login`.
#[derive(Debug, Deserialize)]
struct Login {
    username: String,
    password: String,
}

#[derive(Debug, Default)]
pub(crate) struct Inner {
    pub(crate) users: BTreeMap<u64, User>,
    pub(crate) next_id: u64,
    pub(crate) tokens: HashSet<String>,
    pub(crate) oauth: oauth::OAuthState,
}

/// Shared server state.
#[derive(Clone, Default)]
pub struct AppState {
    pub(crate) inner: Arc<Mutex<Inner>>,
}

impl AppState {
    /// Secret of the confidential OAuth client `curly-service` (random per process).
    pub fn oauth_client_secret(&self) -> String {
        self.inner
            .lock()
            .expect("state lock")
            .oauth
            .client_secret
            .clone()
    }

    /// Creates state seeded with two users and a random OAuth client secret.
    pub fn seeded() -> Self {
        let state = AppState::default();
        state.inner.lock().expect("state lock").oauth.client_secret = random_token();
        {
            let mut inner = state.inner.lock().expect("state lock");
            for (name, email) in [
                ("Ada Lovelace", "ada@example.test"),
                ("Alan Turing", "alan@example.test"),
            ] {
                inner.next_id += 1;
                let id = inner.next_id;
                inner.users.insert(
                    id,
                    User {
                        id,
                        name: name.into(),
                        email: email.into(),
                    },
                );
            }
        }
        state
    }
}

/// Builds the router with every test endpoint.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route(
            "/openapi.yaml",
            get(|| async { ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI_SPEC) }),
        )
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", get(get_user).delete(delete_user))
        .route("/login", post(login))
        .route("/me", get(me))
        .route("/echo", any(echo))
        .route("/xml", get(xml))
        .route("/html", get(html))
        .route("/text", get(|| async { "plain text body\nsecond line\n" }))
        .route("/slow", get(slow))
        .route("/status/{code}", any(status))
        .route("/graphql", post(graphql::handler))
        .route("/ws/echo", get(ws::echo))
        .route("/ws/chat", get(ws::chat))
        .route("/oauth/authorize", get(oauth::authorize))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/stats", get(oauth::stats))
        .with_state(state)
}

async fn list_users(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let limit = q
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let inner = state.inner.lock().expect("state lock");
    let users: Vec<&User> = inner.users.values().take(limit).collect();
    Json(json!({"items": users, "total": inner.users.len()}))
}

async fn get_user(State(state): State<AppState>, Path(id): Path<u64>) -> Response {
    let inner = state.inner.lock().expect("state lock");
    match inner.users.get(&id) {
        Some(u) => Json(u.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found", "id": id})),
        )
            .into_response(),
    }
}

async fn create_user(State(state): State<AppState>, Json(body): Json<NewUser>) -> Response {
    let mut inner = state.inner.lock().expect("state lock");
    inner.next_id += 1;
    let id = inner.next_id;
    let user = User {
        id,
        name: body.name,
        email: body.email,
    };
    inner.users.insert(id, user.clone());
    (
        StatusCode::CREATED,
        [(header::LOCATION, format!("/users/{id}"))],
        Json(user),
    )
        .into_response()
}

async fn delete_user(State(state): State<AppState>, Path(id): Path<u64>) -> StatusCode {
    let mut inner = state.inner.lock().expect("state lock");
    match inner.users.remove(&id) {
        Some(_) => StatusCode::NO_CONTENT,
        None => StatusCode::NOT_FOUND,
    }
}

/// Issues a random bearer token for user `demo` and any non-empty password.
async fn login(State(state): State<AppState>, Json(body): Json<Login>) -> Response {
    if body.username != "demo" || body.password.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid credentials"})),
        )
            .into_response();
    }
    let token = random_token();
    state
        .inner
        .lock()
        .expect("state lock")
        .tokens
        .insert(token.clone());
    Json(json!({"access_token": token, "token_type": "Bearer", "expires_in": 3600})).into_response()
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    let valid = {
        let inner = state.inner.lock().expect("state lock");
        inner.tokens.contains(token) || inner.oauth.access_token_valid(token)
    };
    if valid {
        Json(json!({"username": "demo"})).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"error": "missing or invalid token"})),
        )
            .into_response()
    }
}

/// Reflects the request back as JSON so tests can see exactly what curl sent.
async fn echo(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Json<Value> {
    let headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    Json(json!({
        "method": method.as_str(),
        "path": uri.path(),
        "query": uri.query(),
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
    }))
}

async fn xml() -> Response {
    let body = r#"<?xml version="1.0"?><catalog><book id="1"><title>SICP</title><year>1985</year></book><book id="2"><title>TAOCP</title></book></catalog>"#;
    ([(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

async fn html() -> Response {
    let body = "<!DOCTYPE html><html><head><title>curly</title></head><body><h1>Hello</h1><p>From the test server.</p></body></html>";
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

async fn slow(Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let ms = q
        .get("ms")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(200)
        .min(10_000);
    tokio::time::sleep(Duration::from_millis(ms)).await;
    Json(json!({"slept_ms": ms}))
}

async fn status(Path(code): Path<u16>) -> Response {
    let code = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
    (code, Json(json!({"status": code.as_u16()}))).into_response()
}

/// Returns 32 random bytes as lowercase hex.
pub(crate) fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A server running on a background thread; stops when dropped.
pub struct Handle {
    /// Bound socket address.
    pub addr: SocketAddr,
    /// gRPC listener address.
    pub grpc_addr: SocketAddr,
    state: AppState,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Handle {
    /// Base URL such as `http://127.0.0.1:8787`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Secret of the confidential OAuth client `curly-service`.
    pub fn oauth_client_secret(&self) -> String {
        self.state.oauth_client_secret()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Binds a loopback listener for tokio.
fn bind(port: u16) -> io::Result<std::net::TcpListener> {
    let l = std::net::TcpListener::bind(("127.0.0.1", port))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Starts HTTP on `127.0.0.1:port` and gRPC on `port + 1` (both random when
/// `port` is 0) in a background thread.
pub fn spawn(port: u16) -> io::Result<Handle> {
    let http = bind(port)?;
    let grpc = bind(if port == 0 { 0 } else { port + 1 })?;
    let (addr, grpc_addr) = (http.local_addr()?, grpc.local_addr()?);
    let (tx, rx) = oneshot::channel::<()>();
    let state = AppState::seeded();
    let app_state = state.clone();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let wait = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
                let _ = rx.wait_for(|stop| *stop).await;
            };
            let http = tokio::net::TcpListener::from_std(http).expect("listener");
            let grpc = tokio::net::TcpListener::from_std(grpc).expect("listener");
            let http_task = tokio::spawn(
                axum::serve(http, router(app_state.clone()))
                    .with_graceful_shutdown(wait(stop_rx.clone()))
                    .into_future(),
            );
            let grpc_task = tokio::spawn(grpc::serve(app_state, grpc, wait(stop_rx)));
            let _ = rx.await;
            let _ = stop_tx.send(true);
            let _ = http_task.await;
            let _ = grpc_task.await;
        });
    });
    Ok(Handle {
        addr,
        grpc_addr,
        state,
        shutdown: Some(tx),
        thread: Some(thread),
    })
}

/// Runs HTTP on `port` and gRPC on `port + 1` in the foreground.
pub async fn serve_forever(port: u16) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let grpc_listener = tokio::net::TcpListener::bind(("127.0.0.1", port + 1)).await?;
    let state = AppState::seeded();
    eprintln!(
        "curly-testserver listening on http://{}",
        listener.local_addr()?
    );
    eprintln!("gRPC (with reflection) on {}", grpc_listener.local_addr()?);
    eprintln!(
        "OAuth confidential client: curly-service, secret for this run: {}",
        state.oauth_client_secret()
    );
    eprintln!("OAuth public client (PKCE): curly-test-client");
    let grpc_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = grpc::serve(grpc_state, grpc_listener, std::future::pending()).await {
            eprintln!("gRPC server stopped: {e}");
        }
    });
    axum::serve(listener, router(state)).await
}
