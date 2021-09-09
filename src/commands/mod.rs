use std::borrow::Cow;

use crate::config::Config;
use crate::errors::Error;
use crate::google_calendar::login;
use mrsbfh::commands::command_generate;

pub mod calendars;
pub mod events;

#[command_generate(
    bot_name = "Calendar",
    description = "This bot helps connecting you to the calendar"
)]
enum Commands {
    Calendars,
    Events,
}

async fn do_login(sender: Cow<'_, str>, tx: mrsbfh::Sender) -> Result<(), Error> {
    login(sender.to_string(), tx).await?;
    Ok(())
}
