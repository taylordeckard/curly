//! WebSocket endpoints for tests:
//! - `GET /ws/echo`: sends `{"type":"welcome","session":...}`, then answers
//!   `{"type":"join","room":R}` with `{"type":"joined","room":R}`,
//!   `{"type":"say","text":T}` with `{"type":"message","text":T}`, and echoes
//!   anything else (binary frames are echoed as binary).
//! - `GET /ws/chat`: the same, but the handshake needs a valid bearer token.

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::{AppState, random_token};

/// `GET /ws/echo`.
pub async fn echo(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(session)
}

/// `GET /ws/chat`: requires `Authorization: Bearer <token>`.
pub async fn chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let ok = {
        let inner = state.inner.lock().expect("state lock");
        inner.tokens.contains(&token) || inner.oauth.access_token_valid(&token)
    };
    if !ok {
        return (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
    }
    ws.on_upgrade(session)
}

async fn session(mut socket: WebSocket) {
    let welcome = json!({"type": "welcome", "session": &random_token()[..12]}).to_string();
    if socket.send(Message::Text(welcome.into())).await.is_err() {
        return;
    }
    while let Some(Ok(msg)) = socket.recv().await {
        let reply = match msg {
            Message::Text(t) => {
                let reply = match serde_json::from_str::<Value>(&t) {
                    Ok(v) if v["type"] == "join" => {
                        json!({"type": "joined", "room": v["room"]}).to_string()
                    }
                    Ok(v) if v["type"] == "say" => {
                        json!({"type": "message", "text": v["text"]}).to_string()
                    }
                    _ => t.to_string(),
                };
                Message::Text(reply.into())
            }
            Message::Binary(b) => Message::Binary(b),
            Message::Close(_) => break,
            _ => continue,
        };
        if socket.send(reply).await.is_err() {
            break;
        }
    }
}
