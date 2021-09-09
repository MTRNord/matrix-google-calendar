use crate::{config::Config, google_calendar::start_webserver};
use clap::Clap;
use matrix_sdk::Client;
use mrsbfh::config::Loader;
use oauth2::{
    basic::{BasicClient, BasicTokenResponse},
    CsrfToken, PkceCodeVerifier,
};
use once_cell::sync::{Lazy, OnceCell};
use std::{collections::BTreeMap, error::Error};
use tracing::*;

pub mod commands;
mod config;
mod errors;
mod google_calendar;
mod matrix;

#[derive(Clap)]
#[clap(version = "0.1.0", author = "MTRNord")]
struct Opts {
    #[clap(short, long, default_value = "config.yml")]
    config: String,
}

pub static MATRIX_CLIENT: OnceCell<Client> = OnceCell::new();
pub static LOGIN_SESSIONS_VERIFIER: Lazy<
    tokio::sync::RwLock<BTreeMap<String, (BasicClient, PkceCodeVerifier, CsrfToken)>>,
> = Lazy::new(|| tokio::sync::RwLock::new(BTreeMap::new()));
pub static GOOGLE_SESSIONS: Lazy<tokio::sync::RwLock<BTreeMap<String, BasicTokenResponse>>> =
    Lazy::new(|| tokio::sync::RwLock::new(BTreeMap::new()));
pub static STATE_TO_MXID: Lazy<tokio::sync::RwLock<BTreeMap<String, String>>> =
    Lazy::new(|| tokio::sync::RwLock::new(BTreeMap::new()));

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .pretty()
        .with_thread_names(true)
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting...");
    let opts: Opts = Opts::parse();

    info!("Loading Configs...");
    let config = Config::load(opts.config)?;
    info!("Setting up Client...");
    let client = matrix::setup(config.clone()).await?;

    tokio::spawn(async move {
        start_webserver().await;
    });
    info!("Starting Sync...");
    matrix::start_sync(client, config).await?;

    Ok(())
}
