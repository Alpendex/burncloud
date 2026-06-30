// OAuth callback page - handles redirect from provider with JWT token

use crate::app::Route;
use burncloud_client_shared::auth_context::{use_auth, CurrentUser};
use burncloud_client_shared::i18n::{t, use_i18n};
use burncloud_client_shared::use_toast;
use burncloud_client_shared::utils::storage::ClientState;
use dioxus::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn parse_query(search: &str) -> HashMap<String, String> {
    let query = search.trim_start_matches('?');
    if query.is_empty() {
        return HashMap::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                _ => None,
            }
        })
        .collect()
}

/// OAuth callback component.
/// The `query` parameter contains the full query string from the URL.
#[component]
pub fn OAuthCallbackPage(query: Option<String>) -> Element {
    let i18n = use_i18n();
    let lang = i18n.language;
    let toast = use_toast();
    let navigator = use_navigator();
    let auth = use_auth();

    let query_str = query.unwrap_or_default();
    let params = parse_query(&query_str);
    let token = params.get("token").cloned().unwrap_or_default();
    let username = params.get("username").cloned().unwrap_or_default();
    let user_id = params.get("user_id").cloned().unwrap_or_default();
    let oauth_error = params.get("oauth_error").cloned();

    // Use Arc<AtomicBool> instead of Signal to avoid mutability issues in closures
    let processed = Arc::new(AtomicBool::new(false));

    use_effect(move || {
        if processed.swap(true, Ordering::SeqCst) {
            return;
        }

        let tok = token.clone();
        let uname = username.clone();
        let uid = user_id.clone();
        let err = oauth_error.clone();

        spawn(async move {
            if let Some(e) = err {
                let msg = match e.as_str() {
                    "no_email" => "OAuth provider did not return an email address",
                    "create_failed" => "Failed to create account",
                    "db_error" => "Server error",
                    "token_failed" => "Failed to generate session token",
                    _ => "OAuth login failed",
                };
                toast.error(msg);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                navigator.replace(Route::LoginPage {});
                return;
            }

            if tok.is_empty() {
                toast.error("Invalid OAuth response");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                navigator.replace(Route::LoginPage {});
                return;
            }

            let display_name = if uname.is_empty() { "User" } else { &uname };
            let new_state = ClientState {
                last_username: Some(display_name.to_string()),
                auth_token: Some(tok.clone()),
                user_info: Some(
                    serde_json::to_string(&CurrentUser {
                        id: uid.clone(),
                        username: display_name.to_string(),
                        roles: vec!["user".to_string()],
                    })
                    .unwrap_or_default(),
                ),
                theme: None,
            };
            new_state.save();

            auth.set_auth(
                tok,
                CurrentUser {
                    id: uid,
                    username: display_name.to_string(),
                    roles: vec!["user".to_string()],
                },
            );
            toast.success(t(*lang.read(), "login.success"));
            navigator.replace(Route::Dashboard {});
        });
    });

    rsx! {
        div { class: "login",
            aside { class: "login-brand",
                div { class: "login-brand-header",
                    div {
                        div { class: "login-brand-name", "BurnCloud" }
                        div { class: "login-brand-sublabel", "Enterprise" }
                    }
                }
                div {
                    h1 { class: "login-brand-headline",
                        "Completing "
                        br {}
                        "login..."
                    }
                    p { class: "login-brand-subhead",
                        "You will be redirected momentarily."
                    }
                }
            }

            main { class: "login-form",
                div { class: "flex flex-col items-center justify-center h-full gap-xl",
                    div { class: "bc-spinner" }
                    p { "Completing authentication..." }
                }
            }
        }
    }
}
