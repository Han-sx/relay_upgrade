// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

pub mod types;
// #[cfg(feature = "bitcoin")]
pub mod xgateway_bitcoin;
// #[cfg(feature = "bitcoin")]
pub mod xgateway_bitcoin_bridge;
#[cfg(feature = "dogecoin")]
pub mod xgateway_dogecoin;
#[cfg(feature = "dogecoin")]
pub mod xgateway_dogecoin_bridge;
pub mod xgateway_records;
