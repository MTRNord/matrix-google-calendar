use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientSecrets {
    pub web: ClientSecretsInner,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientSecretsInner {
    pub client_id: String,
    pub project_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
}

impl ClientSecrets {
    pub fn load_clientsecrets() -> Option<Self> {
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
