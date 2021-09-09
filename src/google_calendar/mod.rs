use std::{
    fs::{self, OpenOptions},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::errors::Error;
use axum::{extract, handler::get, http::StatusCode, Router};
use matrix_sdk::events::{room::message::MessageEventContent, AnyMessageEventContent};
use oauth2::{
    basic::{BasicClient, BasicTokenResponse},
    reqwest::async_http_client,
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::{header, ClientBuilder};
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
struct ClientSecrets {
    web: ClientSecretsInner,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientSecretsInner {
    client_id: String,
    project_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_secret: String,
    redirect_uris: Vec<String>,
}

impl ClientSecrets {
    fn load_clientsecrets() -> Option<Self> {
        let path: PathBuf = "clientsecret.json".into();
        let file = std::fs::File::open(path);
        match file {
            Ok(file) => {
                let clientsecrets: Result<Self, serde_json::Error> = serde_json::from_reader(&file);
                match clientsecrets {
                    Ok(clientsecrets) => Some(clientsecrets),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }
}

trait LoadTokenResponse {
    fn get_from_file(mxid: String) -> Option<BasicTokenResponse>;
    fn save_to_file(&self, mxid: String);
}

impl LoadTokenResponse for BasicTokenResponse {
    fn get_from_file(mxid: String) -> Option<BasicTokenResponse> {
        let path: PathBuf = format!("./tokens/{}.json", mxid).into();
        let file = std::fs::File::open(path);
        match file {
            Ok(file) => {
                let clientsecrets: Result<Self, serde_json::Error> = serde_json::from_reader(&file);
                match clientsecrets {
                    Ok(clientsecrets) => Some(clientsecrets),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }

    fn save_to_file(&self, mxid: String) {
        use std::io::Write;

        let mut path = Path::new("./tokens/").to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path).unwrap();
        }
        path.push(format!("{}.json", mxid));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .unwrap();
        let j = serde_json::to_string(self).unwrap();
        file.write_all(j.as_bytes()).unwrap();
    }
}

pub async fn login(mxid: String, tx: mrsbfh::Sender) -> Result<(), Error> {
    let loaded = BasicTokenResponse::get_from_file(mxid.clone());
    if let Some(token) = loaded {
        crate::GOOGLE_SESSIONS
            .write()
            .await
            .insert(mxid.clone(), token);
    };

    let reader = crate::GOOGLE_SESSIONS.read().await;
    if let Some(token) = reader.get(&mxid) {
        if let Some(expiry) = token.expires_in() {
            if expiry.as_secs() != 0 {
                return Ok(());
            } else {
                // TODO do refresh flow
                let _lalalala = "";
                return Ok(());
            }
        }
    }

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    if let Some(secrets) = ClientSecrets::load_clientsecrets() {
        let redirect_uri = if let Some(uri) = secrets.web.redirect_uris.first() {
            uri.clone()
        } else {
            String::from("http://localhost")
        };
        let client = BasicClient::new(
            ClientId::new(secrets.web.client_id.clone()),
            Some(ClientSecret::new(secrets.web.client_secret.clone())),
            AuthUrl::new(secrets.web.auth_uri.clone())?,
            Some(TokenUrl::new(secrets.web.token_uri.clone())?),
        )
        // Google supports OAuth 2.0 Token Revocation (RFC-7009)
        .set_revocation_uri(
            RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
                .expect("Invalid revocation endpoint URL"),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // Set the desired scopes.
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/calendar.readonly".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/calendar".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/calendar.events".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/calendar.events.readonly".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/calendar.settings.readonly".to_string(),
            ))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        {
            crate::STATE_TO_MXID
                .write()
                .await
                .insert(csrf_token.secret().clone(), mxid.clone());
            crate::LOGIN_SESSIONS_VERIFIER
                .write()
                .await
                .insert(mxid, (client, pkce_verifier, csrf_token));
        };

        let content =
            AnyMessageEventContent::RoomMessage(MessageEventContent::notice_plain(format!(
                "Please login using this URL: {}\n\nAfterwards rerun the command!",
                auth_url
            )));
        tx.send(content).await?;
    }

    Ok(())
}

pub async fn start_webserver() {
    let app = Router::new().route("/", get(root));
    let addr = SocketAddr::from(([127, 0, 0, 1], 55555));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root(query_params: extract::Query<GoogleResponse>) -> (StatusCode, &'static str) {
    let mut writer = crate::LOGIN_SESSIONS_VERIFIER.write().await;
    let reader = crate::STATE_TO_MXID.read().await;
    let mxid = reader.get(&query_params.state.clone()).unwrap();
    if let Some((client, pkce_verifier, crsftoken)) = writer.remove(mxid) {
        let request_state = CsrfToken::new(query_params.state.clone());
        let auth_code = AuthorizationCode::new(query_params.code.clone());

        if request_state.secret() == crsftoken.secret() {
            let token_result = client
                .exchange_code(auth_code)
                // Set the PKCE code verifier.
                .set_pkce_verifier(pkce_verifier)
                .request_async(async_http_client)
                .await;
            if let Ok(token) = token_result {
                info!("{}", token.access_token().secret());
                let token: BasicTokenResponse = token;
                token.save_to_file(mxid.clone());
                crate::GOOGLE_SESSIONS
                    .write()
                    .await
                    .insert(mxid.clone(), token);
                return (StatusCode::OK, "Success");
            }
        }
    }

    (StatusCode::INTERNAL_SERVER_ERROR, "Unable to authenticate")
}

#[derive(Deserialize)]
struct GoogleResponse {
    code: String,
    state: String,
}

pub async fn list_calendars(mxid: String) -> Result<Calendars, crate::errors::Error> {
    let reader = crate::GOOGLE_SESSIONS.read().await;
    let auth_token = reader.get(&mxid).unwrap();
    let access_token = auth_token.access_token();

    info!("Got token");

    let mut headers = header::HeaderMap::new();
    let auth_token_val =
        header::HeaderValue::from_str(&format!("Bearer {}", access_token.secret())).unwrap();
    headers.insert("Authorization", auth_token_val);
    let client = ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap();

    info!("Got client");

    let res = client
        .get("https://www.googleapis.com/calendar/v3/users/me/calendarList")
        .send()
        .await?
        .json::<Calendars>()
        .await?;

    info!("Got response");
    Ok(res)
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Calendars {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub next_sync_token: Option<String>,
    pub items: Vec<CalendarListEntry>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CalendarListEntry {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub summary: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub time_zone: Option<String>,
    pub summary_override: Option<String>,
    pub color_id: Option<String>,
    pub background_color: Option<String>,
    pub foreground_color: Option<String>,
    pub hidden: Option<bool>,
    pub selected: Option<bool>,
    pub access_role: String,
    pub primary: Option<bool>,
    pub deleted: Option<bool>,
    pub default_reminders: Vec<CalendarDefaultReminders>,
    pub notification_settings: Option<CalendarNotificationSettings>,
    pub conference_properties: Option<CalendarConferenceParties>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CalendarDefaultReminders {
    pub method: String,
    pub minutes: i64,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CalendarConferenceParties {
    pub allowed_conference_solution_types: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CalendarNotificationSettings {
    pub notifications: Vec<CalendarNotifications>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CalendarNotifications {
    #[serde(rename = "type")]
    pub notifications_type: String,
    pub method: String,
}
