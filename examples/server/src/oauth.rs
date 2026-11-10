//! A minimal OAuth 2.0 provider for tests: authorization code with PKCE (S256),
//! client credentials, and refresh tokens. Consent is granted automatically.
//!
//! Clients:
//! - `curly-test-client`: public client; must use PKCE; loopback redirects only.
//! - `curly-service`: confidential client; secret is random per process.
//!
//! The non-standard form parameter `test_expires_in` lets tests request
//! short-lived access tokens.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use axum::Form;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{AppState, random_token};

/// Public client id (authorization code + PKCE).
pub const PUBLIC_CLIENT: &str = "curly-test-client";
/// Confidential client id (client credentials).
pub const SERVICE_CLIENT: &str = "curly-service";

#[derive(Debug, Clone)]
struct PendingCode {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    scope: String,
}

/// OAuth state kept by the server.
#[derive(Debug, Default)]
pub struct OAuthState {
    /// Secret for [`SERVICE_CLIENT`].
    pub client_secret: String,
    codes: HashMap<String, PendingCode>,
    access: HashMap<String, Instant>,
    refresh: HashSet<String>,
    token_requests: u64,
}

impl OAuthState {
    /// Whether `token` was issued by the token endpoint and has not expired.
    pub fn access_token_valid(&self, token: &str) -> bool {
        self.access
            .get(token)
            .is_some_and(|exp| Instant::now() < *exp)
    }
}

fn error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}

/// `GET /oauth/authorize`: validates the request and redirects back with a code.
pub async fn authorize(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    if get("response_type") != "code" {
        return error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be code",
        );
    }
    if get("client_id") != PUBLIC_CLIENT {
        return error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "unknown client",
        );
    }
    let redirect_uri = get("redirect_uri");
    if !redirect_uri.starts_with("http://127.0.0.1:") {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri must be a loopback address",
        );
    }
    if get("code_challenge_method") != "S256" || get("code_challenge").len() < 43 {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE with S256 is required",
        );
    }
    let code = random_token();
    state.inner.lock().expect("state lock").oauth.codes.insert(
        code.clone(),
        PendingCode {
            client_id: get("client_id"),
            redirect_uri: redirect_uri.clone(),
            challenge: get("code_challenge"),
            scope: get("scope"),
        },
    );
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    Redirect::to(&format!(
        "{redirect_uri}{sep}code={code}&state={}",
        get("state")
    ))
    .into_response()
}

/// Client id and secret from HTTP Basic auth, if present.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(value).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// `POST /oauth/token`: authorization_code, client_credentials, and refresh_token grants.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let get = |k: &str| f.get(k).cloned().unwrap_or_default();
    let mut guard = state.inner.lock().expect("state lock");
    let oauth = &mut guard.oauth;
    oauth.token_requests += 1;
    let (client_id, client_secret) =
        basic_credentials(&headers).unwrap_or_else(|| (get("client_id"), get("client_secret")));
    let scope = match get("grant_type").as_str() {
        "authorization_code" => {
            let Some(pending) = oauth.codes.remove(&get("code")) else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "unknown or used code",
                );
            };
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(get("code_verifier").as_bytes()));
            if pending.client_id != client_id
                || pending.redirect_uri != get("redirect_uri")
                || challenge != pending.challenge
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client, redirect_uri, or code_verifier mismatch",
                );
            }
            pending.scope
        }
        "client_credentials" => {
            if client_id != SERVICE_CLIENT || client_secret != oauth.client_secret {
                return error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "bad client credentials",
                );
            }
            get("scope")
        }
        "refresh_token" => {
            if !oauth.refresh.remove(&get("refresh_token")) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "unknown refresh token",
                );
            }
            get("scope")
        }
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "unsupported grant_type",
            );
        }
    };
    let expires_in: u64 = get("test_expires_in").parse().unwrap_or(3600);
    let access = random_token();
    oauth.access.insert(
        access.clone(),
        Instant::now() + Duration::from_secs(expires_in),
    );
    let mut body = json!({"access_token": access, "token_type": "Bearer", "expires_in": expires_in, "scope": scope});
    if client_id != SERVICE_CLIENT {
        let refresh = random_token();
        oauth.refresh.insert(refresh.clone());
        body["refresh_token"] = json!(refresh);
    }
    Json(body).into_response()
}

/// `GET /oauth/stats`: how many token requests the server has handled.
pub async fn stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"token_requests": state.inner.lock().expect("state lock").oauth.token_requests}))
}
