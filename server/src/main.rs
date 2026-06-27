use std::{
    collections::HashMap,
    env,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{rejection::JsonRejection, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use password_hash::{rand_core::OsRng, SaltString};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
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
    settings_path: PathBuf,
    store: Arc<RwLock<PersistedStore>>,
    settings: Arc<RwLock<ServerSettings>>,
    sessions: Arc<RwLock<HashMap<String, String>>>,
    tls_tests: Arc<RwLock<HashMap<String, PendingTlsTest>>>,
}

#[derive(Clone)]
struct AppConfig {
    port: u16,
    public_origin: String,
    rp_id: String,
    data_dir: PathBuf,
    web_dist: PathBuf,
    caddy_bin: String,
    caddy_site: String,
    caddy_admin_address: String,
    caddy_config_path: PathBuf,
    caddy_storage_dir: PathBuf,
    caddy_http_port: u16,
    caddy_https_port: u16,
}

const TLS_TEST_TTL_MS: u64 = 10 * 60 * 1000;

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerSettings {
    tls: Option<TlsCertificateSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlsCertificateSettings {
    site: String,
    certificate_path: String,
    private_key_path: String,
    updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlsCertificateRequest {
    site: String,
    certificate_path: String,
    private_key_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlsCertificateSaveRequest {
    site: String,
    certificate_path: String,
    private_key_path: String,
    test_id: String,
}

#[derive(Debug, Clone)]
struct PendingTlsTest {
    user_id: String,
    request: TlsCertificateRequest,
    expires_at: u64,
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
#[serde(rename_all = "camelCase")]
struct VaultPutRequest {
    revision: u64,
    items: Vec<VaultItemEnvelope>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TlsSettingsResponse {
    current: Option<TlsCertificateSettings>,
    default_site: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TlsTestResponse {
    ok: bool,
    test_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TlsSaveResponse {
    current: TlsCertificateSettings,
    reloaded: bool,
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
    let settings_path = config.data_dir.join("server-settings.json");
    let store = load_store(&store_path).await.unwrap_or_default();
    let settings = load_settings(&settings_path).await.unwrap_or_default();
    let state = AppState {
        config: config.clone(),
        store_path,
        settings_path,
        store: Arc::new(RwLock::new(store)),
        settings: Arc::new(RwLock::new(settings)),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        tls_tests: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = build_app(state);

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
    tracing::info!(%addr, origin = %config.public_origin, rp_id = %config.rp_id, "starting NoPassword server");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn build_app(state: AppState) -> Router {
    let web_dist = state.config.web_dist.clone();
    let api = Router::new()
        .route("/healthz", get(health))
        .route("/config", get(config_handler))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/vault", get(get_vault).put(put_vault))
        .route("/admin/tls", get(get_tls_settings).put(save_tls_settings))
        .route("/admin/tls/test", post(test_tls_settings))
        .route("/webauthn/status", get(webauthn_status))
        .fallback(api_not_found)
        .with_state(state);

    let index = web_dist.join("index.html");
    let assets = web_dist.join("assets");
    let icons = web_dist.join("icons");
    let manifest = web_dist.join("manifest.webmanifest");
    let favicon = web_dist.join("icons/icon-192.png");

    Router::new()
        .nest("/api", api)
        .nest_service("/assets", ServeDir::new(assets))
        .nest_service("/icons", ServeDir::new(icons))
        .route_service("/manifest.webmanifest", ServeFile::new(manifest))
        .route_service("/favicon.ico", ServeFile::new(favicon))
        .fallback_service(ServeFile::new(index))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        )
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

        let caddy_bin = env::var("NO_PASSWORD_CADDY_BIN").unwrap_or_else(|_| "caddy".to_string());
        let caddy_site =
            env::var("NO_PASSWORD_CADDY_SITE").unwrap_or_else(|_| public_origin.clone());
        let caddy_admin_address = env::var("NO_PASSWORD_CADDY_ADMIN_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:2019".to_string());
        let caddy_storage_dir = env::var("NO_PASSWORD_CADDY_STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("caddy"));
        let caddy_config_path = env::var("NO_PASSWORD_CADDY_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| caddy_storage_dir.join("managed.Caddyfile"));
        let caddy_http_port = env::var("NO_PASSWORD_CADDY_HTTP_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8080);
        let caddy_https_port = env::var("NO_PASSWORD_CADDY_HTTPS_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8443);

        Self {
            port,
            public_origin,
            rp_id,
            data_dir,
            web_dist,
            caddy_bin,
            caddy_site,
            caddy_admin_address,
            caddy_config_path,
            caddy_storage_dir,
            caddy_http_port,
            caddy_https_port,
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

async fn load_settings(path: &PathBuf) -> Result<ServerSettings, ApiError> {
    match tokio::fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| ApiError::Internal),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ServerSettings::default()),
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

async fn save_settings_file(state: &AppState) -> Result<(), ApiError> {
    let snapshot = state.settings.read().await.clone();
    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(|_| ApiError::Internal)?;
    if let Some(parent) = state.settings_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| ApiError::Internal)?;
    }
    tokio::fs::write(&state.settings_path, bytes)
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

async fn get_tls_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TlsSettingsResponse>, ApiError> {
    let _user_id = authenticated_user_id(&state, &headers).await?;
    let settings = state.settings.read().await;
    Ok(Json(TlsSettingsResponse {
        current: settings.tls.clone(),
        default_site: state.config.caddy_site.clone(),
    }))
}

async fn test_tls_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<TlsCertificateRequest>, JsonRejection>,
) -> Result<Json<TlsTestResponse>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let request = normalize_tls_request(parse_json(payload)?)?;
    validate_tls_files(&request).await?;
    validate_caddyfile(&state.config, &request).await?;

    let test_id = Uuid::new_v4().to_string();
    let now = now_ms();
    let mut tests = state.tls_tests.write().await;
    tests.retain(|_, pending| pending.expires_at >= now);
    tests.insert(
        test_id.clone(),
        PendingTlsTest {
            user_id,
            request,
            expires_at: now + TLS_TEST_TTL_MS,
        },
    );

    Ok(Json(TlsTestResponse {
        ok: true,
        test_id,
        message: "certificate configuration passed validation".to_string(),
    }))
}

async fn save_tls_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<TlsCertificateSaveRequest>, JsonRejection>,
) -> Result<Json<TlsSaveResponse>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let req = parse_json(payload)?;
    let request = normalize_tls_request(TlsCertificateRequest {
        site: req.site,
        certificate_path: req.certificate_path,
        private_key_path: req.private_key_path,
    })?;

    let now = now_ms();
    let pending = {
        let mut tests = state.tls_tests.write().await;
        tests.retain(|_, pending| pending.expires_at >= now);
        tests.remove(&req.test_id).ok_or_else(|| {
            ApiError::BadRequest("run a successful certificate test before saving".to_string())
        })?
    };

    if pending.user_id != user_id || pending.request != request {
        return Err(ApiError::BadRequest(
            "certificate settings changed after the last successful test".to_string(),
        ));
    }

    let current = TlsCertificateSettings {
        site: request.site,
        certificate_path: request.certificate_path,
        private_key_path: request.private_key_path,
        updated_at: now,
    };

    reload_caddy_with_tls(&state.config, &current).await?;
    {
        let mut settings = state.settings.write().await;
        settings.tls = Some(current.clone());
    }
    save_settings_file(&state).await?;

    Ok(Json(TlsSaveResponse {
        current,
        reloaded: true,
    }))
}

async fn api_not_found() -> ApiError {
    ApiError::NotFound
}

async fn register(
    State(state): State<AppState>,
    payload: Result<Json<AuthRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let req = parse_json(payload)?;
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
    payload: Result<Json<AuthRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let req = parse_json(payload)?;
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
    payload: Result<Json<VaultPutRequest>, JsonRejection>,
) -> Result<Json<VaultResponse>, ApiError> {
    let req = parse_json(payload)?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    let vault = VaultRecord {
        revision: req.revision,
        items: req.items,
        updated_at: now_ms(),
    };

    {
        let mut store = state.store.write().await;
        let current = store.vaults.get(&user_id).ok_or(ApiError::NotFound)?;
        if req.revision < current.revision {
            return Err(ApiError::Conflict(format!(
                "stale vault revision: current revision is {}",
                current.revision
            )));
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

fn parse_json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload
        .map(|Json(value)| value)
        .map_err(|rejection| ApiError::BadRequest(rejection.body_text()))
}

fn normalize_tls_request(req: TlsCertificateRequest) -> Result<TlsCertificateRequest, ApiError> {
    let site = req.site.trim().to_string();
    reject_caddyfile_unsafe("site", &site)?;
    let parsed_site = Url::parse(&site)
        .map_err(|_| ApiError::BadRequest("site must be a valid HTTPS URL".to_string()))?;
    if parsed_site.scheme() != "https" || parsed_site.host_str().is_none() {
        return Err(ApiError::BadRequest(
            "site must be an HTTPS URL with a hostname".to_string(),
        ));
    }
    if parsed_site.path() != "/"
        || parsed_site.query().is_some()
        || parsed_site.fragment().is_some()
    {
        return Err(ApiError::BadRequest(
            "site must not include a path, query, or fragment".to_string(),
        ));
    }

    let certificate_path = normalize_absolute_path("certificatePath", &req.certificate_path)?;
    let private_key_path = normalize_absolute_path("privateKeyPath", &req.private_key_path)?;

    Ok(TlsCertificateRequest {
        site,
        certificate_path,
        private_key_path,
    })
}

fn normalize_absolute_path(label: &str, value: &str) -> Result<String, ApiError> {
    let path = value.trim().to_string();
    reject_caddyfile_unsafe(label, &path)?;
    if path.is_empty() {
        return Err(ApiError::BadRequest(format!("{label} is required")));
    }
    if !Path::new(&path).is_absolute() {
        return Err(ApiError::BadRequest(format!(
            "{label} must be an absolute path visible inside the container"
        )));
    }
    Ok(path)
}

fn reject_caddyfile_unsafe(label: &str, value: &str) -> Result<(), ApiError> {
    if value
        .chars()
        .any(|ch| ch == '\0' || ch == '\n' || ch == '\r')
    {
        return Err(ApiError::BadRequest(format!(
            "{label} contains invalid characters"
        )));
    }
    Ok(())
}

async fn validate_tls_files(req: &TlsCertificateRequest) -> Result<(), ApiError> {
    ensure_readable_file("certificatePath", &req.certificate_path).await?;
    ensure_readable_file("privateKeyPath", &req.private_key_path).await
}

async fn ensure_readable_file(label: &str, path: &str) -> Result<(), ApiError> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ApiError::BadRequest(format!("{label} does not exist"))
        } else {
            ApiError::BadRequest(format!("{label} is not readable: {error}"))
        }
    })?;

    if !metadata.is_file() {
        return Err(ApiError::BadRequest(format!(
            "{label} must point to a file"
        )));
    }
    if metadata.len() == 0 {
        return Err(ApiError::BadRequest(format!("{label} must not be empty")));
    }

    tokio::fs::File::open(path)
        .await
        .map_err(|error| ApiError::BadRequest(format!("{label} is not readable: {error}")))?;
    Ok(())
}

async fn validate_caddyfile(
    config: &AppConfig,
    req: &TlsCertificateRequest,
) -> Result<(), ApiError> {
    let caddyfile = render_caddyfile(
        config,
        &TlsCertificateSettings {
            site: req.site.clone(),
            certificate_path: req.certificate_path.clone(),
            private_key_path: req.private_key_path.clone(),
            updated_at: 0,
        },
    );
    let path = temporary_caddyfile_path(config, "tls-test");
    write_text_file(&path, &caddyfile).await?;

    let result = run_caddy_command(config, |command| {
        command
            .arg("validate")
            .arg("--config")
            .arg(&path)
            .arg("--adapter")
            .arg("caddyfile");
    })
    .await;

    let _ = tokio::fs::remove_file(&path).await;
    result.map_err(|message| ApiError::BadRequest(format!("Caddy validation failed: {message}")))
}

async fn reload_caddy_with_tls(
    config: &AppConfig,
    settings: &TlsCertificateSettings,
) -> Result<(), ApiError> {
    let caddyfile = render_caddyfile(config, settings);
    let path = temporary_caddyfile_path(config, "tls-reload");
    write_text_file(&path, &caddyfile).await?;

    let result = run_caddy_command(config, |command| {
        command
            .arg("reload")
            .arg("--config")
            .arg(&path)
            .arg("--adapter")
            .arg("caddyfile")
            .arg("--address")
            .arg(&config.caddy_admin_address);
    })
    .await;

    if let Err(message) = result {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(ApiError::BadRequest(format!(
            "Caddy reload failed: {message}"
        )));
    }

    write_text_file(&config.caddy_config_path, &caddyfile).await?;
    let _ = tokio::fs::remove_file(&path).await;
    Ok(())
}

async fn run_caddy_command<F>(config: &AppConfig, configure: F) -> Result<(), String>
where
    F: FnOnce(&mut Command),
{
    let mut command = Command::new(&config.caddy_bin);
    configure(&mut command);
    command
        .env("HOME", &config.data_dir)
        .env("XDG_CONFIG_HOME", config.caddy_storage_dir.join("config"))
        .env("XDG_DATA_HOME", config.caddy_storage_dir.join("data"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = command
        .output()
        .await
        .map_err(|error| format!("could not start {}: {error}", config.caddy_bin))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = [stderr.trim(), stdout.trim()]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    Err(if detail.is_empty() {
        format!("command exited with {}", output.status)
    } else {
        detail
    })
}

fn render_caddyfile(config: &AppConfig, settings: &TlsCertificateSettings) -> String {
    format!(
        "{{\n\tadmin {admin}\n\thttp_port {http_port}\n\thttps_port {https_port}\n\tstorage file_system {{\n\t\troot {storage_root}\n\t}}\n}}\n\n{site} {{\n\ttls {cert} {key}\n\treverse_proxy 127.0.0.1:{server_port}\n}}\n",
        admin = config.caddy_admin_address,
        http_port = config.caddy_http_port,
        https_port = config.caddy_https_port,
        storage_root = caddy_quote(config.caddy_storage_dir.to_string_lossy().as_ref()),
        site = settings.site,
        cert = caddy_quote(&settings.certificate_path),
        key = caddy_quote(&settings.private_key_path),
        server_port = config.port,
    )
}

fn caddy_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn temporary_caddyfile_path(config: &AppConfig, prefix: &str) -> PathBuf {
    config
        .caddy_storage_dir
        .join(format!("{prefix}-{}.Caddyfile", Uuid::new_v4()))
}

async fn write_text_file(path: &Path, content: &str) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| ApiError::Internal)?;
    }
    tokio::fs::write(path, content)
        .await
        .map_err(|_| ApiError::Internal)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header::CONTENT_TYPE, HeaderMap, Method, Request},
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    const TEST_AUTH_SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn api_errors_are_json() {
        let (app, data_dir) = test_app().await;

        let (status, headers, body) = send_json(&app, request(Method::GET, "/api/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_json_content_type(&headers);
        assert_eq!(body["error"], "not found");

        let malformed = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/login")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();
        let (status, headers, body) = send_json(&app, malformed).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_json_content_type(&headers);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .starts_with("bad request: Failed to parse the request body as JSON"));

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn vault_rejects_stale_revisions_and_uses_camel_case() {
        let (app, data_dir) = test_app().await;
        let email = test_email();
        let token = register_user(&app, &email).await;

        let item = json!({
            "id": "item-1",
            "kind": "login",
            "cipher": "opaque-cipher",
            "nonce": "opaque-nonce",
            "updatedAt": 1
        });
        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/vault",
                json!({ "revision": 1, "items": [item] }),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 1);
        assert!(body.get("updatedAt").is_some());
        assert!(body.get("updated_at").is_none());

        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/vault",
                json!({ "revision": 0, "items": [] }),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("stale vault revision"));

        let (status, _, body) =
            send_json(&app, authorized_request(Method::GET, "/api/vault", &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 1);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["cipher"], "opaque-cipher");

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn vault_store_persists_between_app_instances() {
        let config = test_config();
        let data_dir = config.data_dir.clone();
        let app = test_app_with_config(config.clone()).await;
        let email = test_email();
        let token = register_user(&app, &email).await;

        let item = json!({
            "id": "persisted-item",
            "kind": "login",
            "cipher": "persisted-cipher",
            "nonce": "persisted-nonce",
            "updatedAt": 10
        });
        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/vault",
                json!({ "revision": 2, "items": [item] }),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let restarted_app = test_app_with_config(config).await;
        let token = login_user(&restarted_app, &email).await;
        let (status, _, body) = send_json(
            &restarted_app,
            authorized_request(Method::GET, "/api/vault", &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 2);
        assert_eq!(body["items"][0]["cipher"], "persisted-cipher");

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn tls_settings_require_successful_test_before_save() {
        let (app, data_dir) = test_app().await;
        let email = test_email();
        let token = register_user(&app, &email).await;

        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/admin/tls",
                json!({
                    "site": "https://vault.example.test",
                    "certificatePath": "/tmp/fullchain.pem",
                    "privateKeyPath": "/tmp/privkey.pem",
                    "testId": "missing-test"
                }),
                Some(&token),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("run a successful certificate test"));

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn tls_test_rejects_missing_certificate_files() {
        let (app, data_dir) = test_app().await;
        let email = test_email();
        let token = register_user(&app, &email).await;

        let missing_cert = data_dir.join("missing-fullchain.pem");
        let missing_key = data_dir.join("missing-privkey.pem");
        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/admin/tls/test",
                json!({
                    "site": "https://vault.example.test",
                    "certificatePath": missing_cert.to_string_lossy(),
                    "privateKeyPath": missing_key.to_string_lossy()
                }),
                Some(&token),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("certificatePath"));

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn spa_fallback_serves_index_with_success_status() {
        let mut config = test_config();
        config.web_dist = config.data_dir.join("web");
        tokio::fs::create_dir_all(config.web_dist.join("assets"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(config.web_dist.join("icons"))
            .await
            .unwrap();
        tokio::fs::write(
            config.web_dist.join("index.html"),
            "<div id=\"root\"></div>",
        )
        .await
        .unwrap();
        tokio::fs::write(config.web_dist.join("manifest.webmanifest"), "{}")
            .await
            .unwrap();
        tokio::fs::write(config.web_dist.join("assets/app.js"), "console.log('ok');")
            .await
            .unwrap();
        tokio::fs::write(config.web_dist.join("icons/icon-192.png"), "png")
            .await
            .unwrap();

        let data_dir = config.data_dir.clone();
        let app = test_app_with_config(config).await;

        let (status, _, body) = send_text(&app, request(Method::GET, "/nested/client/route")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<div id=\"root\"></div>"));

        let (status, _, body) = send_text(&app, request(Method::GET, "/assets/app.js")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log('ok');");

        let (status, _, body) = send_text(&app, request(Method::GET, "/favicon.ico")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "png");

        cleanup(data_dir).await;
    }

    async fn register_user(app: &Router, email: &str) -> String {
        let (status, _, body) = send_json(
            app,
            json_request(
                Method::POST,
                "/api/auth/register",
                json!({ "email": email, "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        body["token"].as_str().unwrap().to_string()
    }

    async fn login_user(app: &Router, email: &str) -> String {
        let (status, _, body) = send_json(
            app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": email, "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        body["token"].as_str().unwrap().to_string()
    }

    async fn send_json(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "response body is not JSON: {error}: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        (status, headers, body)
    }

    async fn send_text(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        (status, headers, body)
    }

    fn request(method: Method, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    fn authorized_request(method: Method, path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn json_request(method: Method, path: &str, body: Value, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn test_app() -> (Router, PathBuf) {
        let config = test_config();
        let data_dir = config.data_dir.clone();
        (test_app_with_config(config).await, data_dir)
    }

    async fn test_app_with_config(config: AppConfig) -> Router {
        tokio::fs::create_dir_all(&config.data_dir).await.unwrap();
        let store_path = config.data_dir.join("store.json");
        let settings_path = config.data_dir.join("server-settings.json");
        let store = load_store(&store_path).await.unwrap();
        let settings = load_settings(&settings_path).await.unwrap();
        let state = AppState {
            config,
            store_path,
            settings_path,
            store: Arc::new(RwLock::new(store)),
            settings: Arc::new(RwLock::new(settings)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            tls_tests: Arc::new(RwLock::new(HashMap::new())),
        };
        build_app(state)
    }

    fn test_config() -> AppConfig {
        let data_dir = env::temp_dir().join(format!("nopassword-server-test-{}", Uuid::new_v4()));
        let caddy_storage_dir = data_dir.join("caddy");
        AppConfig {
            port: 0,
            public_origin: "http://127.0.0.1:0".to_string(),
            rp_id: "127.0.0.1".to_string(),
            data_dir,
            web_dist: PathBuf::from("../web/dist"),
            caddy_bin: "caddy".to_string(),
            caddy_site: "http://:8080".to_string(),
            caddy_admin_address: "127.0.0.1:2019".to_string(),
            caddy_config_path: caddy_storage_dir.join("managed.Caddyfile"),
            caddy_storage_dir,
            caddy_http_port: 8080,
            caddy_https_port: 8443,
        }
    }

    fn test_email() -> String {
        format!("{}@example.com", Uuid::new_v4())
    }

    fn assert_json_content_type(headers: &HeaderMap) {
        let content_type = headers.get(CONTENT_TYPE).expect("missing content-type");
        assert!(content_type
            .to_str()
            .unwrap()
            .starts_with("application/json"));
    }

    async fn cleanup(data_dir: PathBuf) {
        let _ = tokio::fs::remove_dir_all(data_dir).await;
    }
}
