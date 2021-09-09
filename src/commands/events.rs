use crate::config::Config;
use crate::errors::Error;
use matrix_sdk::identifiers::RoomId;
use matrix_sdk::Client;
use mrsbfh::commands::command;

#[command(help = "`!events` - Displays all events you have.")]
pub async fn events<'a>(
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
    super::do_login(sender.clone().into(), tx).await?;

    Ok(())
}
