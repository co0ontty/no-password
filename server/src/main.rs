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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use password_hash::{
    rand_core::{OsRng, RngCore},
    SaltString,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use tokio::process::Command;
use tokio::sync::RwLock;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::{Host, Url};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    db: SqlitePool,
    startup_auth_secret: Option<String>,
    sessions: Arc<RwLock<HashMap<String, SessionRecord>>>,
    tls_tests: Arc<RwLock<HashMap<String, PendingTlsTest>>>,
}

#[derive(Debug, Clone)]
struct SessionRecord {
    user_id: String,
    auth_hash: String,
}

#[derive(Debug, Clone)]
struct OwnerPasswordReset {
    email: String,
    password: String,
}

#[derive(Clone)]
struct AppConfig {
    port: u16,
    public_origin: String,
    rp_id: String,
    data_dir: PathBuf,
    database_path: PathBuf,
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
const DEFAULT_VAULT_EMAIL: &str = "owner@nopassword.local";

enum CliCommand {
    Serve,
    ResetOwnerPassword,
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
    next_auth_secret: Option<String>,
    kdf: Option<serde_json::Value>,
    wrapped_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountEmailUpdateRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountPasswordUpdateRequest {
    current_auth_secret: String,
    next_auth_secret: String,
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
    owner_email: String,
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
    let command = cli_command_from_args().map_err(|message| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{message}\n\n{}", cli_usage()),
        )
    })?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nopassword_server=info,tower_http=info,axum=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env();

    match command {
        CliCommand::Serve => serve(config).await?,
        CliCommand::ResetOwnerPassword => {
            let reset = reset_owner_password(&config).await?;
            print_reset_owner_password(&reset.email, &reset.password);
        }
    }

    Ok(())
}

async fn serve(config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let db = open_configured_database(&config).await?;
    let startup_auth_secret = if user_count(&db).await? == 0 {
        let startup_password = generate_startup_password();
        print_startup_password(&startup_password);
        Some(derive_auth_secret(&startup_password))
    } else {
        None
    };
    let state = AppState {
        config: config.clone(),
        db,
        startup_auth_secret,
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

fn cli_command_from_args() -> Result<CliCommand, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => Ok(CliCommand::Serve),
        [command] if command == "serve" => Ok(CliCommand::Serve),
        [command] if command == "reset-owner-password" || command == "reset-startup-password" => {
            Ok(CliCommand::ResetOwnerPassword)
        }
        [command] if command == "-h" || command == "--help" || command == "help" => {
            println!("{}", cli_usage());
            std::process::exit(0);
        }
        [command, ..] => Err(format!("unknown command: {command}")),
    }
}

fn cli_usage() -> &'static str {
    "Usage:\n  nopassword-server [serve]\n  nopassword-server reset-owner-password\n\nreset-owner-password rotates the current owner server login password without deleting the SQLite database, vault envelopes, TLS files, or Caddy state."
}

fn build_app(state: AppState) -> Router {
    let web_dist = state.config.web_dist.clone();
    let api = Router::new()
        .route("/healthz", get(health))
        .route("/config", get(config_handler))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/account/email", post(update_account_email))
        .route("/account/password", post(update_account_password))
        .route("/vault", get(get_vault).put(put_vault))
        .route("/admin/tls", get(get_tls_settings).put(save_tls_settings))
        .route("/admin/tls/test", post(test_tls_settings))
        .route("/webauthn/status", get(webauthn_status))
        .fallback(api_not_found)
        .with_state(state);

    let index = web_dist.join("index.html");
    let assets = web_dist.join("assets");
    let icons = web_dist.join("icons");
    let downloads = web_dist.join("downloads");
    let manifest = web_dist.join("manifest.webmanifest");
    let favicon = web_dist.join("icons/icon-192.png");

    Router::new()
        .nest("/api", api)
        .nest_service("/assets", ServeDir::new(assets))
        .nest_service("/icons", ServeDir::new(icons))
        .nest_service("/downloads", ServeDir::new(downloads))
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

fn print_startup_password(password: &str) {
    println!();
    println!("NoPassword startup password: {password}");
    println!("Use this password to initialize the vault on first open.");
    println!();
}

fn print_reset_owner_password(email: &str, password: &str) {
    println!();
    println!("NoPassword owner password reset: {password}");
    println!("Email: {email}");
    println!("Server data was preserved. This does not decrypt a browser vault if its local master password was forgotten.");
    println!();
}

fn derive_auth_secret(password: &str) -> String {
    let digest = Sha256::digest(format!("no-password-auth-v2:{password}"));
    URL_SAFE_NO_PAD.encode(digest)
}

fn hash_auth_secret(auth_secret: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(auth_secret.as_bytes(), &salt)
        .map_err(|_| ApiError::Internal)
        .map(|hash| hash.to_string())
}

fn default_kdf() -> serde_json::Value {
    serde_json::json!({ "name": "PBKDF2-SHA256", "iterations": 310000 })
}

fn generate_startup_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*?";
    let mut bytes = [0u8; 24];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

impl AppConfig {
    fn from_env() -> Self {
        let port = env::var("NO_PASSWORD_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8181);

        let public_origin = env::var("NO_PASSWORD_PUBLIC_ORIGIN")
            .unwrap_or_else(|_| "http://127.0.0.1:8181".to_string());

        let rp_id = env::var("NO_PASSWORD_RP_ID").unwrap_or_else(|_| {
            Url::parse(&public_origin)
                .ok()
                .and_then(|url| url.host_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "127.0.0.1".to_string())
        });

        let data_dir = env::var("NO_PASSWORD_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));

        let database_path = env::var("NO_PASSWORD_DATABASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("nopassword.sqlite3"));

        let web_dist = env::var("NO_PASSWORD_WEB_DIST")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../web/dist"));

        let caddy_bin = env::var("NO_PASSWORD_CADDY_BIN").unwrap_or_else(|_| "caddy".to_string());
        let caddy_site = env::var("NO_PASSWORD_CADDY_SITE")
            .unwrap_or_else(|_| caddy_site_address(&public_origin));
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
            .unwrap_or(8181);
        let caddy_https_port = env::var("NO_PASSWORD_CADDY_HTTPS_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8182);

        Self {
            port,
            public_origin,
            rp_id,
            data_dir,
            database_path,
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

async fn open_database(path: &Path) -> Result<SqlitePool, ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| ApiError::Internal)?;
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .synchronous(SqliteSynchronous::Normal);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(db_error)
}

async fn open_configured_database(config: &AppConfig) -> Result<SqlitePool, ApiError> {
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .map_err(|_| ApiError::Internal)?;
    let db = open_database(&config.database_path).await?;
    initialize_database(&db).await?;
    migrate_legacy_files(&config.data_dir, &db).await?;
    Ok(db)
}

async fn initialize_database(db: &SqlitePool) -> Result<(), ApiError> {
    let statements = [
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            auth_hash TEXT NOT NULL,
            kdf TEXT NOT NULL,
            wrapped_key TEXT,
            created_at INTEGER NOT NULL
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS vaults (
            user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL DEFAULT 0,
            items TEXT NOT NULL DEFAULT '[]',
            updated_at INTEGER NOT NULL DEFAULT 0
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS server_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )
        "#,
    ];

    for statement in statements {
        sqlx::query(statement).execute(db).await.map_err(db_error)?;
    }
    Ok(())
}

async fn migrate_legacy_files(data_dir: &Path, db: &SqlitePool) -> Result<(), ApiError> {
    if user_count(db).await? == 0 {
        let store_path = data_dir.join("store.json");
        match load_store(&store_path).await {
            Ok(store) if !store.users.is_empty() => {
                insert_legacy_store(db, &store).await?;
                tracing::info!(
                    path = %store_path.display(),
                    "migrated legacy JSON store into SQLite database"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    path = %store_path.display(),
                    ?error,
                    "could not migrate legacy JSON store"
                );
            }
        }
    }

    if !server_settings_exists(db).await? {
        let settings_path = data_dir.join("server-settings.json");
        match load_settings(&settings_path).await {
            Ok(settings) if settings.tls.is_some() => {
                save_server_settings(db, &settings).await?;
                tracing::info!(
                    path = %settings_path.display(),
                    "migrated legacy server settings into SQLite database"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    path = %settings_path.display(),
                    ?error,
                    "could not migrate legacy server settings"
                );
            }
        }
    }
    Ok(())
}

async fn insert_legacy_store(db: &SqlitePool, store: &PersistedStore) -> Result<(), ApiError> {
    let mut tx = db.begin().await.map_err(db_error)?;
    for user in store.users.values() {
        let kdf = serde_json::to_string(&user.kdf).map_err(|_| ApiError::Internal)?;
        sqlx::query(
            r#"
            INSERT INTO users (id, email, auth_hash, kdf, wrapped_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.auth_hash)
        .bind(kdf)
        .bind(&user.wrapped_key)
        .bind(to_i64(user.created_at)?)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        let vault = store.vaults.get(&user.id).cloned().unwrap_or_default();
        let items = serde_json::to_string(&vault.items).map_err(|_| ApiError::Internal)?;
        sqlx::query(
            r#"
            INSERT INTO vaults (user_id, revision, items, updated_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(to_i64(vault.revision)?)
        .bind(items)
        .bind(to_i64(vault.updated_at)?)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)
}

async fn user_count(db: &SqlitePool) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await
        .map_err(db_error)
}

async fn server_settings_exists(db: &SqlitePool) -> Result<bool, ApiError> {
    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM server_settings WHERE key = 'server'")
            .fetch_one(db)
            .await
            .map_err(db_error)?;
    Ok(count > 0)
}

async fn load_server_settings(db: &SqlitePool) -> Result<ServerSettings, ApiError> {
    let value =
        sqlx::query_scalar::<_, String>("SELECT value FROM server_settings WHERE key = 'server'")
            .fetch_optional(db)
            .await
            .map_err(db_error)?;

    match value {
        Some(value) => serde_json::from_str(&value).map_err(|_| ApiError::Internal),
        None => Ok(ServerSettings::default()),
    }
}

async fn save_server_settings(db: &SqlitePool, settings: &ServerSettings) -> Result<(), ApiError> {
    let value = serde_json::to_string(settings).map_err(|_| ApiError::Internal)?;
    sqlx::query(
        r#"
        INSERT INTO server_settings (key, value, updated_at)
        VALUES ('server', ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(value)
    .bind(to_i64(now_ms())?)
    .execute(db)
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn find_user_by_email(db: &SqlitePool, email: &str) -> Result<Option<UserRecord>, ApiError> {
    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, i64)>(
        r#"
        SELECT id, email, auth_hash, kdf, wrapped_key, created_at
        FROM users
        WHERE email = ?
        "#,
    )
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;

    row.map(user_from_row).transpose()
}

async fn find_user_by_id(db: &SqlitePool, user_id: &str) -> Result<Option<UserRecord>, ApiError> {
    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, i64)>(
        r#"
        SELECT id, email, auth_hash, kdf, wrapped_key, created_at
        FROM users
        WHERE id = ?
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;

    row.map(user_from_row).transpose()
}

async fn owner_email(db: &SqlitePool) -> Result<String, ApiError> {
    let email = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users ORDER BY created_at ASC, rowid ASC LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(db_error)?;

    Ok(email.unwrap_or_else(|| DEFAULT_VAULT_EMAIL.to_string()))
}

async fn owner_user(db: &SqlitePool) -> Result<Option<UserRecord>, ApiError> {
    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, i64)>(
        r#"
        SELECT id, email, auth_hash, kdf, wrapped_key, created_at
        FROM users
        ORDER BY created_at ASC, rowid ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(db)
    .await
    .map_err(db_error)?;

    row.map(user_from_row).transpose()
}

async fn reset_owner_password(config: &AppConfig) -> Result<OwnerPasswordReset, ApiError> {
    let password = generate_startup_password();
    let email = reset_owner_password_to(config, &password).await?;
    Ok(OwnerPasswordReset { email, password })
}

async fn reset_owner_password_to(config: &AppConfig, password: &str) -> Result<String, ApiError> {
    let db = open_configured_database(config).await?;
    let email = owner_email(&db).await?;
    rotate_owner_password(&db, &email, password).await?;
    Ok(email)
}

async fn rotate_owner_password(
    db: &SqlitePool,
    email: &str,
    password: &str,
) -> Result<(), ApiError> {
    let email = normalize_email(email)?;
    let auth_secret = derive_auth_secret(password);
    let auth_hash = hash_auth_secret(&auth_secret)?;
    let mut tx = db.begin().await.map_err(db_error)?;
    let existing_id = sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;

    let user_id = match existing_id {
        Some(user_id) => {
            sqlx::query("UPDATE users SET auth_hash = ? WHERE id = ?")
                .bind(auth_hash)
                .bind(&user_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
            user_id
        }
        None => {
            let user_id = Uuid::new_v4().to_string();
            let kdf = serde_json::to_string(&default_kdf()).map_err(|_| ApiError::Internal)?;
            sqlx::query(
                r#"
                INSERT INTO users (id, email, auth_hash, kdf, wrapped_key, created_at)
                VALUES (?, ?, ?, ?, NULL, ?)
                "#,
            )
            .bind(&user_id)
            .bind(&email)
            .bind(auth_hash)
            .bind(kdf)
            .bind(to_i64(now_ms())?)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            user_id
        }
    };

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO vaults (user_id, revision, items, updated_at)
        VALUES (?, 0, '[]', 0)
        "#,
    )
    .bind(&user_id)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;

    tx.commit().await.map_err(db_error)
}

async fn update_user_email(
    db: &SqlitePool,
    user_id: &str,
    email: &str,
) -> Result<UserRecord, ApiError> {
    let mut user = find_user_by_id(db, user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    if let Some(existing) = find_user_by_email(db, email).await? {
        if existing.id != user.id {
            return Err(ApiError::Conflict("account already exists".to_string()));
        }
    }

    sqlx::query("UPDATE users SET email = ? WHERE id = ?")
        .bind(email)
        .bind(user_id)
        .execute(db)
        .await
        .map_err(db_error)?;

    user.email = email.to_string();
    Ok(user)
}

async fn update_user_password(
    db: &SqlitePool,
    user_id: &str,
    current_auth_secret: &str,
    next_auth_secret: &str,
) -> Result<UserRecord, ApiError> {
    if current_auth_secret.len() < 32 || next_auth_secret.len() < 32 {
        return Err(ApiError::BadRequest("authSecret is too short".to_string()));
    }

    let mut user = find_user_by_id(db, user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let parsed_hash = PasswordHash::new(&user.auth_hash).map_err(|_| ApiError::Internal)?;
    Argon2::default()
        .verify_password(current_auth_secret.as_bytes(), &parsed_hash)
        .map_err(|_| ApiError::Unauthorized)?;

    let auth_hash = hash_auth_secret(next_auth_secret)?;
    sqlx::query("UPDATE users SET auth_hash = ? WHERE id = ?")
        .bind(&auth_hash)
        .bind(user_id)
        .execute(db)
        .await
        .map_err(db_error)?;

    user.auth_hash = auth_hash;
    Ok(user)
}

async fn insert_user_with_vault(db: &SqlitePool, user: &UserRecord) -> Result<(), ApiError> {
    let mut tx = db.begin().await.map_err(db_error)?;
    let kdf = serde_json::to_string(&user.kdf).map_err(|_| ApiError::Internal)?;
    sqlx::query(
        r#"
        INSERT INTO users (id, email, auth_hash, kdf, wrapped_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&user.id)
    .bind(&user.email)
    .bind(&user.auth_hash)
    .bind(kdf)
    .bind(&user.wrapped_key)
    .bind(to_i64(user.created_at)?)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;

    sqlx::query(
        r#"
        INSERT INTO vaults (user_id, revision, items, updated_at)
        VALUES (?, 0, '[]', 0)
        "#,
    )
    .bind(&user.id)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;

    tx.commit().await.map_err(db_error)
}

async fn load_vault(db: &SqlitePool, user_id: &str) -> Result<VaultRecord, ApiError> {
    let row = sqlx::query_as::<_, (i64, String, i64)>(
        r#"
        SELECT revision, items, updated_at
        FROM vaults
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;

    match row {
        Some((revision, items, updated_at)) => Ok(VaultRecord {
            revision: to_u64(revision),
            items: serde_json::from_str(&items).map_err(|_| ApiError::Internal)?,
            updated_at: to_u64(updated_at),
        }),
        None => Ok(VaultRecord::default()),
    }
}

async fn save_vault(
    db: &SqlitePool,
    user_id: &str,
    req: VaultPutRequest,
) -> Result<VaultRecord, ApiError> {
    let mut tx = db.begin().await.map_err(db_error)?;
    let current = sqlx::query_as::<_, (i64,)>("SELECT revision FROM vaults WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        .ok_or(ApiError::NotFound)?;

    let current_revision = to_u64(current.0);
    if req.revision < current_revision {
        return Err(ApiError::Conflict(format!(
            "stale vault revision: current revision is {}",
            current_revision
        )));
    }

    let vault = VaultRecord {
        revision: req.revision,
        items: req.items,
        updated_at: now_ms(),
    };
    let items = serde_json::to_string(&vault.items).map_err(|_| ApiError::Internal)?;
    sqlx::query(
        r#"
        UPDATE vaults
        SET revision = ?, items = ?, updated_at = ?
        WHERE user_id = ?
        "#,
    )
    .bind(to_i64(vault.revision)?)
    .bind(items)
    .bind(to_i64(vault.updated_at)?)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;

    tx.commit().await.map_err(db_error)?;
    Ok(vault)
}

fn user_from_row(
    row: (String, String, String, String, Option<String>, i64),
) -> Result<UserRecord, ApiError> {
    let (id, email, auth_hash, kdf, wrapped_key, created_at) = row;
    Ok(UserRecord {
        id,
        email,
        auth_hash,
        kdf: serde_json::from_str(&kdf).map_err(|_| ApiError::Internal)?,
        wrapped_key,
        created_at: to_u64(created_at),
    })
}

fn to_i64(value: u64) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::Internal)
}

fn to_u64(value: i64) -> u64 {
    value.max(0) as u64
}

fn db_error(error: sqlx::Error) -> ApiError {
    tracing::error!(?error, "database operation failed");
    ApiError::Internal
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "nopassword-server",
    })
}

async fn config_handler(State(state): State<AppState>) -> Result<Json<ConfigResponse>, ApiError> {
    Ok(Json(ConfigResponse {
        app_name: "NoPassword",
        public_origin: state.config.public_origin,
        rp_id: state.config.rp_id,
        passkey_server_api: "planned",
        owner_email: owner_email(&state.db).await?,
    }))
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
    let settings = load_server_settings(&state.db).await?;
    Ok(Json(TlsSettingsResponse {
        current: settings.tls,
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
    save_server_settings(
        &state.db,
        &ServerSettings {
            tls: Some(current.clone()),
        },
    )
    .await?;

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

    if user_count(&state.db).await? > 0 {
        return Err(ApiError::Conflict("account already exists".to_string()));
    }

    if state.startup_auth_secret.as_deref() != Some(req.auth_secret.as_str()) {
        return Err(ApiError::Unauthorized);
    }

    let auth_hash = hash_auth_secret(&req.auth_secret)?;

    let user = UserRecord {
        id: Uuid::new_v4().to_string(),
        email: email.clone(),
        auth_hash,
        kdf: req.kdf.unwrap_or_else(|| serde_json::json!({})),
        wrapped_key: req.wrapped_key,
        created_at: now_ms(),
    };

    insert_user_with_vault(&state.db, &user).await?;

    let token = issue_session(&state, &user).await;
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
    if req.auth_secret.len() < 32 {
        return Err(ApiError::BadRequest("authSecret is too short".to_string()));
    }
    let mut user = owner_user(&state.db).await?.ok_or(ApiError::Unauthorized)?;

    let parsed_hash = PasswordHash::new(&user.auth_hash).map_err(|_| ApiError::Internal)?;
    Argon2::default()
        .verify_password(req.auth_secret.as_bytes(), &parsed_hash)
        .map_err(|_| ApiError::Unauthorized)?;

    if let Some(next_auth_secret) = req.next_auth_secret {
        if next_auth_secret.len() < 32 {
            return Err(ApiError::BadRequest("authSecret is too short".to_string()));
        }
        if next_auth_secret != req.auth_secret {
            let auth_hash = hash_auth_secret(&next_auth_secret)?;
            sqlx::query("UPDATE users SET auth_hash = ? WHERE id = ?")
                .bind(&auth_hash)
                .bind(&user.id)
                .execute(&state.db)
                .await
                .map_err(db_error)?;
            user.auth_hash = auth_hash;
        }
    }

    let token = issue_session(&state, &user).await;
    Ok(Json(AuthResponse {
        token,
        profile: Profile {
            id: user.id,
            email: user.email,
        },
    }))
}

async fn update_account_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AccountEmailUpdateRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let req = parse_json(payload)?;
    let email = normalize_email(&req.email)?;
    let user = update_user_email(&state.db, &user_id, &email).await?;
    let token = issue_session(&state, &user).await;

    Ok(Json(AuthResponse {
        token,
        profile: Profile {
            id: user.id,
            email: user.email,
        },
    }))
}

async fn update_account_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AccountPasswordUpdateRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let req = parse_json(payload)?;
    let user = update_user_password(
        &state.db,
        &user_id,
        &req.current_auth_secret,
        &req.next_auth_secret,
    )
    .await?;
    let token = issue_session(&state, &user).await;

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
    let vault = load_vault(&state.db, &user_id).await?;

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
    let vault = save_vault(&state.db, &user_id, req).await?;

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
        "{{\n\tadmin {admin}\n\thttp_port {http_port}\n\thttps_port {https_port}\n\tstorage file_system {{\n\t\troot {storage_root}\n\t}}\n}}\n\nhttp://:{http_port} {{\n\treverse_proxy 127.0.0.1:{server_port}\n}}\n\nhttps://:{https_port} {{\n\ttls {cert} {key}\n\treverse_proxy 127.0.0.1:{server_port}\n}}\n",
        admin = config.caddy_admin_address,
        http_port = config.caddy_http_port,
        https_port = config.caddy_https_port,
        storage_root = caddy_quote(config.caddy_storage_dir.to_string_lossy().as_ref()),
        cert = caddy_quote(&settings.certificate_path),
        key = caddy_quote(&settings.private_key_path),
        server_port = config.port,
    )
}

fn caddy_site_address(site: &str) -> String {
    let Ok(url) = Url::parse(site) else {
        return site.to_string();
    };
    if url.scheme() != "https" {
        return site.to_string();
    }
    let Some(port) = url.port() else {
        return site.to_string();
    };
    let Some(host) = url.host() else {
        return site.to_string();
    };
    let host = match host {
        Host::Domain(value) => value.to_string(),
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => format!("[{value}]"),
    };
    format!("{host}:{port}")
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

async fn issue_session(state: &AppState, user: &UserRecord) -> String {
    let token = format!("np_{}", Uuid::new_v4().simple());
    state.sessions.write().await.insert(
        token.clone(),
        SessionRecord {
            user_id: user.id.clone(),
            auth_hash: user.auth_hash.clone(),
        },
    );
    token
}

async fn authenticated_user_id(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    let session = state
        .sessions
        .read()
        .await
        .get(token)
        .cloned()
        .ok_or(ApiError::Unauthorized)?;

    let current_auth_hash =
        sqlx::query_scalar::<_, String>("SELECT auth_hash FROM users WHERE id = ?")
            .bind(&session.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(db_error)?;

    if current_auth_hash.as_deref() != Some(session.auth_hash.as_str()) {
        state.sessions.write().await.remove(token);
        return Err(ApiError::Unauthorized);
    }

    Ok(session.user_id)
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
    async fn account_email_update_preserves_vault_without_rekeying_login() {
        let (app, data_dir) = test_app().await;
        let old_email = test_email();
        let new_email = test_email();
        let old_token = register_user(&app, &old_email).await;

        let item = json!({
            "id": "renamed-owner-item",
            "kind": "login",
            "cipher": "renamed-owner-cipher",
            "nonce": "renamed-owner-nonce",
            "updatedAt": 12
        });
        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/vault",
                json!({ "revision": 4, "items": [item] }),
                Some(&old_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/account/email",
                json!({
                    "email": new_email.clone()
                }),
                Some(&old_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["profile"]["email"], new_email);
        let new_token = body["token"].as_str().unwrap().to_string();

        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": old_email.clone(), "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": new_email.clone(), "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &old_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, body) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &new_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 4);
        assert_eq!(body["items"][0]["cipher"], "renamed-owner-cipher");

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn account_password_update_rekeys_login_and_preserves_vault() {
        let (app, data_dir) = test_app().await;
        let email = test_email();
        let old_token = register_user(&app, &email).await;
        let next_auth_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let item = json!({
            "id": "password-change-item",
            "kind": "login",
            "cipher": "password-change-cipher",
            "nonce": "password-change-nonce",
            "updatedAt": 12
        });
        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/vault",
                json!({ "revision": 5, "items": [item] }),
                Some(&old_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/account/password",
                json!({
                    "currentAuthSecret": TEST_AUTH_SECRET,
                    "nextAuthSecret": next_auth_secret
                }),
                Some(&old_token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["profile"]["email"], email);
        let new_token = body["token"].as_str().unwrap().to_string();

        let (status, _, _) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &old_token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": email.clone(), "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": test_email(), "authSecret": next_auth_secret }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, body) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &new_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 5);
        assert_eq!(body["items"][0]["cipher"], "password-change-cipher");

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn login_can_migrate_auth_hash_without_changing_account_name() {
        let (app, data_dir) = test_app().await;
        let email = test_email();
        let old_token = register_user(&app, &email).await;
        let migrated_auth_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({
                    "email": test_email(),
                    "authSecret": TEST_AUTH_SECRET,
                    "nextAuthSecret": migrated_auth_secret
                }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["profile"]["email"], email);

        let (status, _, _) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &old_token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": email, "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let token =
            login_user_with_secret(&app, "anything@example.com", migrated_auth_secret).await;
        let (status, _, _) =
            send_json(&app, authorized_request(Method::GET, "/api/vault", &token)).await;
        assert_eq!(status, StatusCode::OK);

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn additional_registration_is_rejected() {
        let (app, data_dir) = test_app().await;
        let first_email = test_email();
        let second_email = test_email();
        let _first_token = register_user(&app, &first_email).await;

        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/register",
                json!({ "email": second_email, "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "conflict: account already exists");

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn reset_owner_password_preserves_vault_data() {
        let config = test_config();
        let data_dir = config.data_dir.clone();
        let app = test_app_with_config(config.clone()).await;
        let token = register_user(&app, DEFAULT_VAULT_EMAIL).await;

        let item = json!({
            "id": "owner-item",
            "kind": "login",
            "cipher": "owner-cipher",
            "nonce": "owner-nonce",
            "updatedAt": 12
        });
        let (status, _, _) = send_json(
            &app,
            json_request(
                Method::PUT,
                "/api/vault",
                json!({ "revision": 3, "items": [item] }),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        reset_owner_password_to(&config, "new-owner-password")
            .await
            .unwrap();

        let restarted_app = test_app_with_config(config).await;
        let (status, _, _) = send_json(
            &restarted_app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": DEFAULT_VAULT_EMAIL, "authSecret": TEST_AUTH_SECRET }),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let token = login_user_with_secret(
            &restarted_app,
            DEFAULT_VAULT_EMAIL,
            &derive_auth_secret("new-owner-password"),
        )
        .await;
        let (status, _, body) = send_json(
            &restarted_app,
            authorized_request(Method::GET, "/api/vault", &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 3);
        assert_eq!(body["items"][0]["cipher"], "owner-cipher");

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn reset_owner_password_invalidates_existing_sessions() {
        let config = test_config();
        let data_dir = config.data_dir.clone();
        let app = test_app_with_config(config.clone()).await;
        let old_token = register_user(&app, DEFAULT_VAULT_EMAIL).await;

        reset_owner_password_to(&config, "rotated-owner-password")
            .await
            .unwrap();

        let (status, _, _) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &old_token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let new_token = login_user_with_secret(
            &app,
            DEFAULT_VAULT_EMAIL,
            &derive_auth_secret("rotated-owner-password"),
        )
        .await;
        let (status, _, _) = send_json(
            &app,
            authorized_request(Method::GET, "/api/vault", &new_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn legacy_json_store_imports_into_sqlite() {
        let config = test_config();
        let data_dir = config.data_dir.clone();
        tokio::fs::create_dir_all(&data_dir).await.unwrap();

        let email = test_email();
        let user_id = Uuid::new_v4().to_string();
        let salt = SaltString::generate(&mut OsRng);
        let auth_hash = Argon2::default()
            .hash_password(TEST_AUTH_SECRET.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let item = VaultItemEnvelope {
            id: "legacy-item".to_string(),
            kind: "login".to_string(),
            cipher: "legacy-cipher".to_string(),
            nonce: "legacy-nonce".to_string(),
            updated_at: 20,
        };
        let store = PersistedStore {
            users: HashMap::from([(
                email.clone(),
                UserRecord {
                    id: user_id.clone(),
                    email: email.clone(),
                    auth_hash,
                    kdf: json!({ "name": "PBKDF2-SHA256", "iterations": 310000 }),
                    wrapped_key: Some("legacy-wrapped-key".to_string()),
                    created_at: 10,
                },
            )]),
            vaults: HashMap::from([(
                user_id,
                VaultRecord {
                    revision: 4,
                    items: vec![item],
                    updated_at: 30,
                },
            )]),
        };
        tokio::fs::write(
            data_dir.join("store.json"),
            serde_json::to_vec_pretty(&store).unwrap(),
        )
        .await
        .unwrap();

        let app = test_app_with_config(config).await;
        let token = login_user(&app, &email).await;
        let (status, _, body) =
            send_json(&app, authorized_request(Method::GET, "/api/vault", &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], 4);
        assert_eq!(body["items"][0]["cipher"], "legacy-cipher");
        assert!(data_dir.join("nopassword-test.sqlite3").exists());

        cleanup(data_dir).await;
    }

    #[tokio::test]
    async fn first_registration_requires_startup_secret() {
        let (app, data_dir) = test_app().await;
        let email = test_email();
        let (status, _, body) = send_json(
            &app,
            json_request(
                Method::POST,
                "/api/auth/register",
                json!({ "email": email, "authSecret": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }),
                None,
            ),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "unauthorized");

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
        tokio::fs::create_dir_all(config.web_dist.join("downloads"))
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
        tokio::fs::write(
            config.web_dist.join("downloads/no-password-browser-extension.zip"),
            "zip",
        )
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

        let (status, _, body) = send_text(
            &app,
            request(Method::GET, "/downloads/no-password-browser-extension.zip"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "zip");

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
        login_user_with_secret(app, email, TEST_AUTH_SECRET).await
    }

    async fn login_user_with_secret(app: &Router, email: &str, auth_secret: &str) -> String {
        let (status, _, body) = send_json(
            app,
            json_request(
                Method::POST,
                "/api/auth/login",
                json!({ "email": email, "authSecret": auth_secret }),
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
        let db = open_database(&config.database_path).await.unwrap();
        initialize_database(&db).await.unwrap();
        migrate_legacy_files(&config.data_dir, &db).await.unwrap();
        let state = AppState {
            config,
            db,
            startup_auth_secret: Some(TEST_AUTH_SECRET.to_string()),
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
            database_path: caddy_storage_dir
                .parent()
                .unwrap()
                .join("nopassword-test.sqlite3"),
            web_dist: PathBuf::from("../web/dist"),
            caddy_bin: "caddy".to_string(),
            caddy_site: "http://:8181".to_string(),
            caddy_admin_address: "127.0.0.1:2019".to_string(),
            caddy_config_path: caddy_storage_dir.join("managed.Caddyfile"),
            caddy_storage_dir,
            caddy_http_port: 8181,
            caddy_https_port: 8182,
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
