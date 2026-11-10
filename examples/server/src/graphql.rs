//! `POST /graphql`: a small GraphQL API over the same users as the REST endpoints.
//! Introspection is enabled so curly can cache and validate against the schema.

use async_graphql::{
    Context, EmptySubscription, ID, InputObject, Object, Result as GqlResult, Schema, SimpleObject,
};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, header};

use crate::{AppState, User};

/// A user.
#[derive(SimpleObject, Clone)]
#[graphql(name = "User", complex)]
struct GqlUser {
    /// Identifier.
    id: ID,
    /// Display name.
    name: String,
    /// Email address.
    email: String,
}

impl From<User> for GqlUser {
    fn from(u: User) -> Self {
        GqlUser {
            id: ID(u.id.to_string()),
            name: u.name,
            email: u.email,
        }
    }
}

#[async_graphql::ComplexObject]
impl GqlUser {
    /// Every other user.
    async fn friends(&self, ctx: &Context<'_>, first: Option<i32>) -> Vec<GqlUser> {
        let state = ctx.data_unchecked::<AppState>();
        let inner = state.inner.lock().expect("state lock");
        let n = first.map(|f| f.max(0) as usize).unwrap_or(usize::MAX);
        inner
            .users
            .values()
            .filter(|u| u.id.to_string() != self.id.0)
            .take(n)
            .cloned()
            .map(GqlUser::from)
            .collect()
    }
}

/// Input for `createUser`.
#[derive(InputObject)]
struct NewUserInput {
    /// Display name.
    name: String,
    /// Email address.
    email: String,
}

/// Whether the request carried a valid bearer token.
struct Authed(bool);

/// Query root.
pub struct QueryRoot;

#[Object(name = "Query")]
impl QueryRoot {
    /// One user by id.
    async fn user(&self, ctx: &Context<'_>, id: ID) -> Option<GqlUser> {
        let state = ctx.data_unchecked::<AppState>();
        let id: u64 = id.parse().ok()?;
        state
            .inner
            .lock()
            .expect("state lock")
            .users
            .get(&id)
            .cloned()
            .map(GqlUser::from)
    }

    /// Users, optionally limited.
    async fn users(&self, ctx: &Context<'_>, limit: Option<i32>) -> Vec<GqlUser> {
        let state = ctx.data_unchecked::<AppState>();
        let n = limit.map(|l| l.max(0) as usize).unwrap_or(usize::MAX);
        state
            .inner
            .lock()
            .expect("state lock")
            .users
            .values()
            .take(n)
            .cloned()
            .map(GqlUser::from)
            .collect()
    }

    /// The caller's username; requires `Authorization: Bearer <token>`.
    async fn me(&self, ctx: &Context<'_>) -> GqlResult<String> {
        if ctx.data_unchecked::<Authed>().0 {
            Ok("demo".into())
        } else {
            Err("missing or invalid token".into())
        }
    }
}

/// Mutation root.
pub struct MutationRoot;

#[Object(name = "Mutation")]
impl MutationRoot {
    /// Creates a user.
    async fn create_user(&self, ctx: &Context<'_>, input: NewUserInput) -> GqlUser {
        let state = ctx.data_unchecked::<AppState>();
        let mut inner = state.inner.lock().expect("state lock");
        inner.next_id += 1;
        let id = inner.next_id;
        let user = User {
            id,
            name: input.name,
            email: input.email,
        };
        inner.users.insert(id, user.clone());
        user.into()
    }
}

/// Handles `POST /graphql`.
pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<async_graphql::Request>,
) -> Json<async_graphql::Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let authed = {
        let inner = state.inner.lock().expect("state lock");
        inner.tokens.contains(&token) || inner.oauth.access_token_valid(&token)
    };
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .finish();
    Json(schema.execute(req.data(Authed(authed))).await)
}
