// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex convert error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("scale codec error: {0}")]
    Codec(#[from] codec::Error),
    #[error("bitcoin rpc request error: {0}")]
    BtcRpc(#[from] reqwest::Error),
    #[error("rpc request error: {0}")]
    Rpc(#[from] subxt::Error),
    #[error("rpc request timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("btc key error: {0}")]
    BtcKey(#[from] light_bitcoin::keys::Error),
    #[error("btc serialize/deserialize error: {0}")]
    BtcSerDe(#[from] light_bitcoin::serialization::Error),
    #[error("other error: {0}")]
    Other(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Error::Other(err.to_string())
    }
}
impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Other(err)
    }
}
