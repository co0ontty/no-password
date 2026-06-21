use std::{
    collections::HashMap,
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use password_hash::{rand_core::OsRng, SaltString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    store_path: PathBuf,
    store: Arc<RwLock<PersistedStore>>,
    sessions: Arc<RwLock<HashMap<String, String>>>,
}

#[derive(Clone)]
struct AppConfig {
    port: u16,
    public_origin: String,
    rp_id: String,
    data_dir: PathBuf,
    web_dist: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedStore {
    users: HashMap<String, UserRecord>,
    vaults: HashMap<String, VaultRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRecord {
    id: String,
    email: String,
    auth_hash: String,
    kdf: serde_json::Value,
    wrapped_key: Option<String>,
    created_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VaultRecord {
    revision: u64,
    items: Vec<VaultItemEnvelope>,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultItemEnvelope {
    id: String,
    kind: String,
    cipher: String,
    nonce: String,
    updated_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequest {
    email: String,
    auth_secret: String,
    kdf: Option<serde_json::Value>,
    wrapped_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
    profile: Profile,
}

#[derive(Debug, Serialize)]
struct Profile {
    id: String,
    email: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigResponse {
    app_name: &'static str,
    public_origin: String,
    rp_id: String,
    passkey_server_api: &'static str,
}

#[derive(Debug, Deserialize)]
struct VaultPutRequest {
    revision: u64,
    items: Vec<VaultItemEnvelope>,
}

#[derive(Debug, Serialize)]
struct VaultResponse {
    revision: u64,
    items: Vec<VaultItemEnvelope>,
    updated_at: u64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(thiserror::Error, Debug)]
enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("not found")]
    NotFound,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(serde_json::json!({
            "error": self.to_string()
        }));

        (status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nopassword_server=info,tower_http=info,axum=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env();
    tokio::fs::create_dir_all(&config.data_dir).await?;

    let store_path = config.data_dir.join("store.json");
    let store = load_store(&store_path).await.unwrap_or_default();
    let state = AppState {
        config: config.clone(),
        store_path,
        store: Arc::new(RwLock::new(store)),
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    let api = Router::new()
        .route("/healthz", get(health))
        .route("/config", get(config_handler))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/vault", get(get_vault).put(put_vault))
        .route("/webauthn/status", get(webauthn_status))
        .with_state(state);

    let index = config.web_dist.join("index.html");
    let static_files = ServeDir::new(&config.web_dist).not_found_service(ServeFile::new(index));

    let app = Router::new()
        .nest("/api", api)
        .fallback_service(static_files)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        );

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
    tracing::info!(%addr, origin = %config.public_origin, rp_id = %config.rp_id, "starting NoPassword server");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

impl AppConfig {
    fn from_env() -> Self {
        let port = env::var("NO_PASSWORD_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8080);

        let public_origin = env::var("NO_PASSWORD_PUBLIC_ORIGIN")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

        let rp_id = env::var("NO_PASSWORD_RP_ID").unwrap_or_else(|_| {
            Url::parse(&public_origin)
                .ok()
                .and_then(|url| url.host_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "127.0.0.1".to_string())
        });

        let data_dir = env::var("NO_PASSWORD_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));

        let web_dist = env::var("NO_PASSWORD_WEB_DIST")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../web/dist"));

        Self {
            port,
            public_origin,
            rp_id,
            data_dir,
            web_dist,
        }
    }
}

async fn load_store(path: &PathBuf) -> Result<PersistedStore, ApiError> {
    match tokio::fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| ApiError::Internal),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PersistedStore::default()),
        Err(_) => Err(ApiError::Internal),
    }
}

async fn save_store(state: &AppState) -> Result<(), ApiError> {
    let snapshot = state.store.read().await.clone();
    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(|_| ApiError::Internal)?;
    if let Some(parent) = state.store_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| ApiError::Internal)?;
    }
    tokio::fs::write(&state.store_path, bytes)
        .await
        .map_err(|_| ApiError::Internal)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "nopassword-server",
    })
}

async fn config_handler(State(state): State<AppState>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        app_name: "NoPassword",
        public_origin: state.config.public_origin,
        rp_id: state.config.rp_id,
        passkey_server_api: "planned",
    })
}

async fn webauthn_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "planned",
        "note": "WebAuthn ceremonies are reserved in the API contract and will be backed by webauthn-rs."
    }))
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    if req.auth_secret.len() < 32 {
        return Err(ApiError::BadRequest("authSecret is too short".to_string()));
    }

    {
        let store = state.store.read().await;
        if store.users.contains_key(&email) {
            return Err(ApiError::Conflict("account already exists".to_string()));
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let auth_hash = Argon2::default()
        .hash_password(req.auth_secret.as_bytes(), &salt)
        .map_err(|_| ApiError::Internal)?
        .to_string();

    let user = UserRecord {
        id: Uuid::new_v4().to_string(),
        email: email.clone(),
        auth_hash,
        kdf: req.kdf.unwrap_or_else(|| serde_json::json!({})),
        wrapped_key: req.wrapped_key,
        created_at: now_ms(),
    };

    {
        let mut store = state.store.write().await;
        store.users.insert(email.clone(), user.clone());
        store.vaults.insert(user.id.clone(), VaultRecord::default());
    }
    save_store(&state).await?;

    let token = issue_session(&state, &user.id).await;
    Ok(Json(AuthResponse {
        token,
        profile: Profile {
            id: user.id,
            email: user.email,
        },
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    let user = {
        let store = state.store.read().await;
        store
            .users
            .get(&email)
            .cloned()
            .ok_or(ApiError::Unauthorized)?
    };

    let parsed_hash = PasswordHash::new(&user.auth_hash).map_err(|_| ApiError::Internal)?;
    Argon2::default()
        .verify_password(req.auth_secret.as_bytes(), &parsed_hash)
        .map_err(|_| ApiError::Unauthorized)?;

    let token = issue_session(&state, &user.id).await;
    Ok(Json(AuthResponse {
        token,
        profile: Profile {
            id: user.id,
            email: user.email,
        },
    }))
}

async fn get_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultResponse>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let vault = {
        let store = state.store.read().await;
        store.vaults.get(&user_id).cloned().unwrap_or_default()
    };

    Ok(Json(VaultResponse {
        revision: vault.revision,
        items: vault.items,
        updated_at: vault.updated_at,
    }))
}

async fn put_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VaultPutRequest>,
) -> Result<Json<VaultResponse>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let vault = VaultRecord {
        revision: req.revision,
        items: req.items,
        updated_at: now_ms(),
    };

    {
        let mut store = state.store.write().await;
        if !store.vaults.contains_key(&user_id) {
            return Err(ApiError::NotFound);
        }
        store.vaults.insert(user_id, vault.clone());
    }
    save_store(&state).await?;

    Ok(Json(VaultResponse {
        revision: vault.revision,
        items: vault.items,
        updated_at: vault.updated_at,
    }))
}

async fn issue_session(state: &AppState, user_id: &str) -> String {
    let token = format!("np_{}", Uuid::new_v4().simple());
    state
        .sessions
        .write()
        .await
        .insert(token.clone(), user_id.to_string());
    token
}

async fn authenticated_user_id(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    state
        .sessions
        .read()
        .await
        .get(token)
        .cloned()
        .ok_or(ApiError::Unauthorized)
}

fn normalize_email(email: &str) -> Result<String, ApiError> {
    let normalized = email.trim().to_ascii_lowercase();
    if normalized.len() < 3 || !normalized.contains('@') {
        return Err(ApiError::BadRequest("email is invalid".to_string()));
    }
    Ok(normalized)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
