use thiserror::Error as ThisError;

#[allow(clippy::enum_variant_names)]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    TokioMPSCSendError(
        #[from] tokio::sync::mpsc::error::SendError<matrix_sdk::events::AnyMessageEventContent>,
    ),
}
