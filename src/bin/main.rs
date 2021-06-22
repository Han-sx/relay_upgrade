// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use btc_relay::{logger, CmdConfig, Result, Service};

#[tokio::main]
async fn main() -> Result<()> {
    let conf = CmdConfig::init()?;

    logger::init(&conf)?;

    // #[cfg(any(feature = "dogecoin", feature = "bitcoin"))]
    Service::relay(conf).await?;

    Ok(())
}
