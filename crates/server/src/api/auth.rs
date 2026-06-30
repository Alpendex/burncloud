use crate::api::response::{err, ok};
use crate::AppState;
use axum::{
    body::Body,
    extract::{Json, Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use burncloud_database_user::{UserAccount, UserDatabase};
use burncloud_service_user::UserServiceError;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Deserialize)]
pub struct RegisterDto {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginDto {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordDto {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordDto {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Serialize)]
struct AuthData {
    id: String,
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
    token: String,
}

fn get_jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| "default-secret-key-change-in-production".to_string())
}

pub fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = get_jwt_secret();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

// ── OAuth Callback Types ─────────────────────────────────────────

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: Option<String>,
}

// ── Public Routes ────────────────────────────────────────────────

/// Public routes - no authentication required
/// - /api/auth/register - Registration
/// - /api/auth/login - Login
/// - /api/auth/forgot-password - Forgot password
/// - /api/auth/reset-password - Reset password
/// - /api/auth/google - Google OAuth
/// - /api/auth/github - GitHub OAuth
/// - /api/auth/google/callback - Google OAuth callback
/// - /api/auth/github/callback - GitHub OAuth callback
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/register", post(create_user))
        .route("/api/auth/login", post(login))
        .route("/api/auth/forgot-password", post(forgot_password))
        .route("/api/auth/reset-password", post(reset_password))
        .route("/api/auth/google", get(oauth_google))
        .route("/api/auth/github", get(oauth_github))
        .route("/api/auth/google/callback", get(oauth_google_callback))
        .route("/api/auth/github/callback", get(oauth_github_callback))
}

/// Protected routes - authentication required
/// Currently empty, but available for future protected auth endpoints
/// (e.g., logout, change-password)
pub fn protected_routes() -> Router<AppState> {
    Router::new()
}

#[tracing::instrument(skip(state, payload), fields(username = %payload.username))]
async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterDto>,
) -> impl IntoResponse {
    match state
        .user_service
        .register_user(
            &state.db,
            &payload.username,
            &payload.password,
            payload.email,
        )
        .await
    {
        Ok(user_id) => {
            let roles = state
                .user_service
                .get_user_roles(&state.db, &user_id)
                .await
                .unwrap_or_default();
            match state
                .user_service
                .generate_token(&user_id, &payload.username)
            {
                Ok(auth_token) => ok(AuthData {
                    id: user_id,
                    username: payload.username,
                    roles: Some(roles),
                    token: auth_token.token,
                })
                .into_response(),
                Err(e) => {
                    tracing::error!("JWT generation failed: {}", e);
                    err("Failed to generate authentication token").into_response()
                }
            }
        }
        Err(UserServiceError::UserAlreadyExists) => err("Username already exists").into_response(),
        Err(e) => {
            tracing::error!("Registration error: {}", e);
            err("Registration failed").into_response()
        }
    }
}

#[tracing::instrument(skip(state, payload), fields(username = %payload.username))]
async fn login(State(state): State<AppState>, Json(payload): Json<LoginDto>) -> impl IntoResponse {
    match state
        .user_service
        .login_user(&state.db, &payload.username, &payload.password)
        .await
    {
        Ok(auth_token) => {
            let roles = state
                .user_service
                .get_user_roles(&state.db, &auth_token.user_id)
                .await
                .unwrap_or_default();

            ok(AuthData {
                id: auth_token.user_id,
                username: auth_token.username,
                roles: Some(roles),
                token: auth_token.token,
            })
            .into_response()
        }
        Err(UserServiceError::UserNotFound) => err("User not found").into_response(),
        Err(UserServiceError::InvalidCredentials) => err("Invalid credentials").into_response(),
        Err(e) => {
            tracing::error!("Login error: {}", e);
            err("Login failed").into_response()
        }
    }
}

async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordDto>,
) -> impl IntoResponse {
    match state
        .user_service
        .request_password_reset(&state.db, &payload.email)
        .await
    {
        Ok(_reset_token) => {
            tracing::info!("Password reset token generated for {}", payload.email);
            ok(serde_json::json!({ "message": "If the email exists, a reset token has been generated" })).into_response()
        }
        Err(UserServiceError::UserNotFound) => {
            ok(serde_json::json!({ "message": "If the email exists, a reset token has been generated" })).into_response()
        }
        Err(e) => {
            tracing::error!("Forgot password error: {}", e);
            err("Failed to process password reset request").into_response()
        }
    }
}

async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordDto>,
) -> impl IntoResponse {
    match state
        .user_service
        .reset_password(&state.db, &payload.token, &payload.new_password)
        .await
    {
        Ok(()) => ok(serde_json::json!({ "message": "Password reset successful" })).into_response(),
        Err(UserServiceError::InvalidCredentials) => {
            err("Invalid or expired reset token").into_response()
        }
        Err(e) => {
            tracing::error!("Reset password error: {}", e);
            err("Password reset failed").into_response()
        }
    }
}

async fn oauth_google(State(_state): State<AppState>) -> impl IntoResponse {
    match burncloud_service_user::UserService::oauth_url("google") {
        Ok(url) => ok(serde_json::json!({ "url": url })).into_response(),
        Err(e) => {
            tracing::error!("Google OAuth URL error: {}", e);
            err("Failed to generate Google OAuth URL").into_response()
        }
    }
}

async fn oauth_github(State(_state): State<AppState>) -> impl IntoResponse {
    match burncloud_service_user::UserService::oauth_url("github") {
        Ok(url) => ok(serde_json::json!({ "url": url })).into_response(),
        Err(e) => {
            tracing::error!("GitHub OAuth URL error: {}", e);
            err("Failed to generate GitHub OAuth URL").into_response()
        }
    }
}

// ── OAuth Callback Handlers ──────────────────────────────────────

/// Exchange Google auth code for user info (email, name).
async fn exchange_google_code(code: &str) -> Result<(String, String), String> {
    let client_id = env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| "GOOGLE_CLIENT_ID not configured".to_string())?;
    let client_secret = env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| "GOOGLE_CLIENT_SECRET not configured".to_string())?;
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| {
        "http://localhost:3000/api/auth/google/callback".to_string()
    });

    let token_resp: serde_json::Value = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_ref()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| format!("Token exchange request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| "No access_token in response".to_string())?
        .to_string();

    let user_info: serde_json::Value = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| format!("User info request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse user info: {e}"))?;

    let email = user_info["email"].as_str().unwrap_or("").to_string();
    let name = user_info["name"].as_str().unwrap_or(&email).to_string();
    Ok((email, name))
}

/// Exchange GitHub auth code for user info (email, name).
async fn exchange_github_code(code: &str) -> Result<(String, String), String> {
    let client_id = env::var("GITHUB_CLIENT_ID")
        .map_err(|_| "GITHUB_CLIENT_ID not configured".to_string())?;
    let client_secret = env::var("GITHUB_CLIENT_SECRET")
        .map_err(|_| "GITHUB_CLIENT_SECRET not configured".to_string())?;
    let redirect_uri = env::var("GITHUB_REDIRECT_URI").unwrap_or_else(|_| {
        "http://localhost:3000/api/auth/github/callback".to_string()
    });

    let token_resp: serde_json::Value = reqwest::Client::new()
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code.as_ref()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await
        .map_err(|e| format!("Token exchange request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| "No access_token in response".to_string())?
        .to_string();

    let emails: Vec<serde_json::Value> = reqwest::Client::new()
        .get("https://api.github.com/user/emails")
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "burncloud")
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| format!("GitHub emails request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse emails: {e}"))?;
    let email = emails
        .iter()
        .find(|e| e["primary"].as_bool().unwrap_or(false))
        .and_then(|e| e["email"].as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let user_info: serde_json::Value = reqwest::Client::new()
        .get("https://api.github.com/user")
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "burncloud")
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| format!("GitHub user info request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse user info: {e}"))?;
    let login = user_info["login"].as_str().unwrap_or(&email).to_string();
    let name = user_info["name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or(&login)
        .to_string();

    Ok((email, name))
}

/// Google OAuth callback: exchange code, find/create user, redirect with JWT.
async fn oauth_google_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let (email, name) = match exchange_google_code(&query.code).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Google OAuth exchange failed: {e}");
            return (
                StatusCode::FOUND,
                [("Location", format!("{base_url}/login?oauth_error=true"))],
            )
                .into_response();
        }
    };

    handle_oauth_user(state, &email, &name, "google").await
}

/// GitHub OAuth callback: exchange code, find/create user, redirect with JWT.
async fn oauth_github_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let (email, name) = match exchange_github_code(&query.code).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("GitHub OAuth exchange failed: {e}");
            return (
                StatusCode::FOUND,
                [("Location", format!("{base_url}/login?oauth_error=true"))],
            )
                .into_response();
        }
    };

    handle_oauth_user(state, &email, &name, "github").await
}

/// Shared OAuth user handling: find or create user, generate JWT, redirect to frontend.
async fn handle_oauth_user(
    state: AppState,
    email: &str,
    name: &str,
    provider: &str,
) -> Response {
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    if email.is_empty() {
        tracing::error!("OAuth {provider} returned no email");
        return (
            StatusCode::FOUND,
            [("Location", format!("{base_url}/login?oauth_error=no_email"))],
        )
            .into_response();
    }

    let existing = UserDatabase::get_user_by_email(&state.db, email).await;

    let (user_id, username) = match existing {
        Ok(Some(user)) => (user.id, user.username),
        Ok(None) => {
            let pwd_hash =
                // OAuth users log in via provider, never via password. Use a throwaway hash.
                "$2b$12$LJ3m4ys3Lk0TSwHnbfOM6eJkMFODLDmUBRqfHms6PBOe3t2n0z9O".to_string();
            let new_user = UserAccount {
                id: uuid::Uuid::new_v4().to_string(),
                username: name.to_string(),
                email: Some(email.to_string()),
                password_hash: Some(pwd_hash),
                github_id: None,
                status: 1,
                balance_usd: 10_000_000_000,
                balance_cny: 0,
                preferred_currency: Some("USD".to_string()),
            };
            match UserDatabase::create_user(&state.db, &new_user).await {
                Ok(_) => {
                    let _ = UserDatabase::assign_role(&state.db, &new_user.id, "user").await;
                    (new_user.id, new_user.username)
                }
                Err(e) => {
                    tracing::error!("Failed to create OAuth user: {e}");
                    return (
                        StatusCode::FOUND,
                        [("Location", format!("{base_url}/login?oauth_error=create_failed"))],
                    )
                        .into_response();
                }
            }
        }
        Err(e) => {
            tracing::error!("DB error looking up OAuth user: {e}");
            return (
                StatusCode::FOUND,
                [("Location", format!("{base_url}/login?oauth_error=db_error"))],
            )
                .into_response();
        }
    };

    match state.user_service.generate_token(&user_id, &username) {
        Ok(auth_token) => {
            tracing::info!("OAuth {provider} login successful: {email} -> {username}");
            let safe_username = username.replace(" ", "%20");
            let safe_id = user_id.replace(" ", "%20");
            let redirect_url = format!("{base_url}/oauth/callback?token={}&username={}&user_id={}", auth_token.token, safe_username, safe_id);
            (StatusCode::FOUND, [("Location", redirect_url)]).into_response()
        }
        Err(e) => {
            tracing::error!("JWT generation failed for OAuth user: {e}");
            (
                StatusCode::FOUND,
                [("Location", format!("{base_url}/login?oauth_error=token_failed"))],
            )
                .into_response()
        }
    }
}

// ── Auth Middleware ───────────────────────────────────────────────

/// Authentication middleware for protected routes.
/// Validates JWT token from Authorization header and injects Claims into request extensions.
#[tracing::instrument(skip_all)]
pub async fn auth_middleware(mut req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            token
        } else {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    match verify_jwt(token) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            Ok(next.run(req).await)
        }
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}
