use crate::config::Config;
use crate::errors::Error;
use crate::google_calendar::list_calendars;
use matrix_sdk::events::room::message::MessageEventContent;
use matrix_sdk::events::AnyMessageEventContent;
use matrix_sdk::identifiers::RoomId;
use matrix_sdk::Client;
use mrsbfh::commands::command;
use tracing::info;

#[command(help = "`!calendars` - Displays all calendars you have.")]
pub async fn calendars<'a>(
    _client: Client,
    tx: mrsbfh::Sender,
    _config: Config<'a>,
    sender: String,
    _room_id: RoomId,
    mut _args: Vec<&str>,
) -> Result<(), Error>
where
    Config<'a>: mrsbfh::config::Loader + Clone,
{
    // Required in case there are new things to request permissions for
    super::do_login(sender.clone().into(), tx.clone()).await?;

    let calendars = list_calendars(sender.clone()).await?;
    info!("{:#?}", calendars);
    for calendar in calendars.items {
        let content =
            AnyMessageEventContent::RoomMessage(MessageEventContent::notice_plain(format!(
                "ID: {}, Summary: {}, Description: {:?}",
                calendar.id, calendar.summary, calendar.description
            )));
        tx.send(content).await?;
    }
    Ok(())
}
