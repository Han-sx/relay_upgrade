use codec::{Decode, Encode};

use light_bitcoin::{
    chain::{BlockHeader as BtcBlockHeader, Transaction as BtcTransaction},
    primitives::H256,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum VoteResult {
    Unfinish,
    Finish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum BtcTxType {
    Withdrawal,
    Deposit,
    HotAndCold,
    TrusteeTransition,
    Irrelevance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default, Encode, Decode)]
pub struct BtcTxState {
    pub tx_type: BtcTxType,
    pub result: BtcTxResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Encode, Decode)]
pub struct BtcHeaderIndex {
    pub hash: H256,
    pub height: u32,
}

#[derive(Clone, Debug, PartialEq, Default, Encode, Decode)]
pub struct BtcHeaderInfo {
    pub header: BtcBlockHeader,
    pub height: u32,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct BtcWithdrawalProposal<AccountId> {
    pub sig_state: VoteResult,
    pub withdrawal_id_list: Vec<u32>,
    pub tx: BtcTransaction,
    pub trustee_list: Vec<(AccountId, bool)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum BtcTxResult {
    Success,
    Failed,
}

impl Default for BtcTxResult {
    fn default() -> Self {
        BtcTxResult::Failed
    }
}

impl Default for BtcTxType {
    fn default() -> Self {
        BtcTxType::Irrelevance
    }
}
