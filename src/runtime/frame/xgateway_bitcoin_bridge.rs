use codec::Encode;

use std::marker::PhantomData;

use subxt::{balances::Balances, module, system::System, Call, Store};

use xp_gateway_bitcoin_v2::types::{IssueRequest, RedeemRequest, Vault};

type BtcAddress = Vec<u8>;
type RequestId = u128;

#[module]
#[rustfmt::skip]
pub trait XGatewayBitcoinBridge: Balances + System {
    #![event_type(RequestId)]
    #![event_type(BtcAddress)]
}

// ===================================================
// Storage
// ===================================================

#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct IssueRequestsStore<T: XGatewayBitcoinBridge> {
    #[store(returns = IssueRequest<T::AccountId, T::BlockNumber, T::Balance>)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    pub id: RequestId,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct RedeemRequestsStore<T: XGatewayBitcoinBridge> {
    #[store(returns = RedeemRequest<T::AccountId, T::BlockNumber, T::Balance>)]
    pub _marker: PhantomData<T>,
    pub id: RequestId,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct VaultsStore<T: XGatewayBitcoinBridge> {
    #[store(returns = Vault<T::BlockNumber, T::Balance>)]
    pub account: T::AccountId,
}

// ===================================================
// Call
// ===================================================
#[derive(Clone, Debug, Eq, PartialEq, Call, Encode)]
pub struct ExecuteIssue<T: XGatewayBitcoinBridge> {
    pub(crate) _marker: PhantomData<T>,
    pub request_id: RequestId,
    pub tx_id: Vec<u8>,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Call, Encode)]
pub struct ExecuteRedeem<T: XGatewayBitcoinBridge> {
    pub(crate) _marker: PhantomData<T>,
    pub request_id: RequestId,
    pub tx_id: Vec<u8>,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}
