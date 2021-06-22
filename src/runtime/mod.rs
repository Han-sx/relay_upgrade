// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

pub mod frame;
pub mod primitives;

use frame::xgateway_records::{WithdrawalRecord, WithdrawalRecordId};
use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;

pub use subxt::Signer;
use subxt::{
    balances::{AccountData, Balances},
    extrinsic::DefaultExtra,
    register_default_type_sizes,
    system::System,
    EventTypeRegistry, PairSigner, Runtime,
};

use self::frame::types::*;

// #[cfg(feature = "bitcoin")]
use self::frame::{xgateway_bitcoin::*, xgateway_bitcoin_bridge::*};
#[cfg(feature = "dogecoin")]
use self::frame::{xgateway_dogecoin::*, xgateway_dogecoin_bridge::*};

use self::{
    frame::xgateway_records::*,
    primitives::{
        AccountId, Address, Balance, BlockNumber, Extrinsic, Hash, Header, Index, Signature,
    },
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChainXNodeRuntime;

impl Runtime for ChainXNodeRuntime {
    type Signature = Signature;
    type Extra = ChainXExtra<Self>;

    fn register_type_sizes(event_type_registry: &mut EventTypeRegistry<Self>) {
        event_type_registry.with_x_gateway_records();

        #[cfg(feature = "dogecoin")]
        event_type_registry.with_x_gateway_dogecoin();
        #[cfg(feature = "dogecoin")]
        event_type_registry.with_x_gateway_dogecoin_bridge();

        // #[cfg(feature = "bitcoin")]
        event_type_registry.with_x_gateway_bitcoin();
        // #[cfg(feature = "bitcoin")]
        event_type_registry.with_x_gateway_bitcoin_bridge();

        //x_system
        event_type_registry.register_type_size::<H256>("H256");
        event_type_registry.register_type_size::<BtcTxResult>("BtcTxResult");
        event_type_registry.register_type_size::<BtcTxType>("BtcTxType");
        event_type_registry.register_type_size::<BtcTxState>("BtcTxState");

        //x_gateway_records
        event_type_registry.register_type_size::<WithdrawalRecordId>("WithdrawalRecordId");
        event_type_registry.register_type_size::<WithdrawalRecord<
            <Self as System>::AccountId,
            <Self as Balances>::Balance,
            <Self as System>::BlockNumber,
        >>("WithdrawalRecord");

        event_type_registry.register_type_size::<Balance>("Balance");
        event_type_registry.register_type_size::<Balance>("AmountOf<T>");
        event_type_registry.register_type_size::<Balance>("BalanceOf<T>");
        event_type_registry.register_type_size::<AccountId>("AccountId");
        event_type_registry.register_type_size::<AccountId>("T::AccountId");
        event_type_registry
            .register_type_size::<AccountId>("<T as frame_system::Config>::AccountId");

        event_type_registry.register_type_size::<BlockNumber>("BlockNumber");
        event_type_registry.register_type_size::<BlockNumber>("BlockNumberFor<T>");
        event_type_registry.register_type_size::<u8>("AssetType");
        event_type_registry.register_type_size::<u8>("Chain");
        event_type_registry.register_type_size::<u8>("CurrencyIdOf<T>");
        event_type_registry.register_type_size::<Hash>("Hash");
        event_type_registry.register_type_size::<u32>("SessionIndex");
        event_type_registry.register_type_size::<u32>("TradingPairId");
        event_type_registry.register_type_size::<u32>("PriceFluctuation");

        event_type_registry.register_type_size::<Vec<u8>>(
            "OrderExecutedInfo<AccountId, Balance, BlockNumber, Price>",
        );
        event_type_registry.register_type_size::<Vec<u8>>(
            "Order<TradingPairId, AccountId, Balance, Price, BlockNumber>",
        );

        register_default_type_sizes(event_type_registry);
    }
}

impl System for ChainXNodeRuntime {
    type Index = Index;
    type BlockNumber = BlockNumber;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Address = Address;
    type Header = Header;
    type Extrinsic = Extrinsic;
    type AccountData = AccountData<<Self as Balances>::Balance>;
}

impl Balances for ChainXNodeRuntime {
    type Balance = Balance;
}

#[cfg(feature = "dogecoin")]
impl XGatewayDogecoin for ChainXNodeRuntime {}
#[cfg(feature = "dogecoin")]
impl XGatewayDogecoinBridge for ChainXNodeRuntime {}

// #[cfg(feature = "bitcoin")]
impl XGatewayBitcoin for ChainXNodeRuntime {}
// #[cfg(feature = "bitcoin")]
impl XGatewayBitcoinBridge for ChainXNodeRuntime {}

impl XGatewayRecords for ChainXNodeRuntime {}

/// ChainX `SignedExtra` for ChainX runtime.
pub type ChainXExtra<T> = DefaultExtra<T>;

/// ChainX `Pair` for ChainX runtime.
pub type ChainXPair = sp_core::sr25519::Pair;

/// ChainX `PairSigner` for ChainX runtime.
pub type ChainXPairSigner = PairSigner<ChainXNodeRuntime, ChainXPair>;
