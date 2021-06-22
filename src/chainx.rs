// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use std::time::Duration;

use futures::future;
use subxt::{
    balances::AccountData,
    system::{AccountInfo, AccountStoreExt},
    Client, ClientBuilder,
};
use tokio::time;

use light_bitcoin::{
    chain::BlockHeader as BtcBlockHeader,
    keys::{MultiAddress as BtcAddress, Network as BtcNetwork},
    primitives::{hash_rev, H256},
    serialization::serialize,
};

use xp_gateway_bitcoin::{BtcTxTypeDetector, RequestInfo, RequestMetaType};

use crate::runtime::frame::types::*;

#[cfg(feature = "dogecoin")]
use crate::runtime::frame::{
    xgateway_dogecoin::*,
    xgateway_dogecoin_bridge::{IssueRequestsStoreExt, RedeemRequestsStoreExt, VaultsStoreExt},
};

// #[cfg(feature = "bitcoin")]
use crate::runtime::frame::{
    xgateway_bitcoin::*,
    xgateway_bitcoin_bridge::{IssueRequestsStoreExt, RedeemRequestsStoreExt, VaultsStoreExt},
};

use crate::{
    error::{Error, Result},
    runtime::{
        primitives::{AccountId, Balance},
        ChainXNodeRuntime, ChainXPairSigner,
    },
};

#[derive(Clone)]
pub struct ChainX {
    pub client: Client<ChainXNodeRuntime>,
    timeout: u64,

    pub btc_network: BtcNetwork,
    pub btc_min_deposit: u64,
    pub btc_withdrawal_fee: u64,
    pub btc_tx_detector: BtcTxTypeDetector,
}

// #[cfg(any(feature = "dogecoin", feature = "bitcoin"))]
impl ChainX {
    pub async fn new<U: Into<String>>(url: U, timeout: u64) -> Result<Self, Error> {
        let client = ClientBuilder::new().set_url(url);
        let client = client.skip_type_sizes_check().build().await;
        let client = client?;

        let (btc_network, btc_min_deposit, btc_withdrawal_fee) = future::join3(
            client.network_id(None),
            client.btc_min_deposit(None),
            client.btc_withdrawal_fee(None),
        )
        .await;

        let btc_network = btc_network?;
        let btc_min_deposit = btc_min_deposit?;
        let btc_withdrawal_fee = btc_withdrawal_fee?;

        info!(
            "[ChainX|new] ChainX Info: [\
                ChainX Genesis: {:?}, \
                Bitcoin Network: {:?}, Bitcoin Min Deposit: {:?}, Bitcoin Withdrawal Fee: {:?}\
            ]",
            client.genesis(),
            btc_network,
            btc_min_deposit,
            btc_withdrawal_fee
        );
        // assert_eq!(chainx_network, ChainXNetwork::Testnet);
        // assert_eq!(btc_network, BtcNetwork::Mainnet);
        // assert_eq!(btc_min_deposit, 100_000); // 0.001 BTC
        // assert_eq!(btc_withdrawal_fee, 500_000); // 0.005 BTC

        let btc_tx_detector = BtcTxTypeDetector::new(btc_network, btc_min_deposit);

        Ok(Self {
            client,
            timeout,
            btc_network,
            btc_min_deposit,
            btc_withdrawal_fee,
            btc_tx_detector,
        })
    }

    pub fn parse_request_id(key: sp_core::storage::StorageKey) -> u128 {
        const STORAGE_PREFIX_LEN: usize = 64;
        const TWOX_HASH_LEN: usize = 16;
        let key = hex::encode(&key.0);
        let hashed_key_key = &key[STORAGE_PREFIX_LEN..];
        let key = &hashed_key_key[TWOX_HASH_LEN..];
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(hex::decode(key).expect("key is valid; qed").as_slice());
        //TODO(wangyafei): maybe wrong
        u128::from_le_bytes(request_id)
    }

    pub fn parse_vec_to_address(data: &[u8]) -> BtcAddress {
        std::str::from_utf8(&data)
            .expect("address data is valid; qed")
            .parse()
            .expect("address is valid; qed")
    }

    pub async fn make_xbridge_requests_info(
        &self,
    ) -> Result<Vec<RequestInfo<crate::runtime::primitives::AccountId>>> {
        let mut infos = vec![];

        let mut iter = self.client.issue_requests_iter(None).await?;
        while let Some((key, value)) = iter.next().await? {
            let output_addr = value.outer_address;
            let amount = value.amount;
            let account = value.requester;
            let req_id = Self::parse_request_id(key);
            infos.push(RequestInfo {
                vault_addr: Some(Self::parse_vec_to_address(&output_addr)),
                requester_addr: None,
                amount: amount as u64,
                requester: account,
                request_type: RequestMetaType::Issue,
                request_id: req_id,
            })
        }

        let mut iter = self.client.redeem_requests_iter(None).await?;
        while let Some((key, value)) = iter.next().await? {
            if value.reimburse {
                continue;
            }
            let requester_addr = value.outer_address;
            let vault_addr = self.client.vaults(value.vault, None).await?.wallet;
            let amount = value.amount;
            let requester = value.requester;
            let req_id = Self::parse_request_id(key);
            infos.push(RequestInfo {
                vault_addr: Some(Self::parse_vec_to_address(&vault_addr)),
                requester_addr: Some(Self::parse_vec_to_address(&requester_addr)),
                amount: amount as u64,
                requester,
                request_type: RequestMetaType::Redeem,
                request_id: req_id,
            })
        }
        println!(
            "[Service|make_xbridge_requests_info] current focus information {:?}",
            infos
        );
        Ok(infos)
    }

    pub async fn free_pcx_balance(&self, account_id: &AccountId) -> Result<Balance, Error> {
        let account_info: AccountInfo<ChainXNodeRuntime> =
            self.client.account(&account_id, None).await?;
        let account_data: AccountData<Balance> = account_info.data;
        let free = account_data.free;
        info!(
            "[ChainX|free_pcx_balance] `{:?}` PCX Free = {:?}",
            account_id, free
        );
        // Less than 0.5 PCX in the account
        if free < 50_000_000 {
            warn!("`{:?}` PCX Free < 0.5 PCX", account_id);
            return Err(Error::Other(format!(
                "Free PCX Balance of `{:?}` < 0.5",
                account_id
            )));
        }
        Ok(free)
    }

    pub async fn chain_best_index(&self, block_chain_type: &str) -> Result<BtcHeaderIndex, Error> {
        let best_index = self.client.best_index(None).await?;
        info!(
            "[ChainX|{}_best_index] Height #{}, Hash: {:?}",
            block_chain_type,
            best_index.height,
            hash_rev(best_index.hash)
        );
        Ok(best_index)
    }

    pub async fn chain_confirmed_index(&self, block_chain_type: &str) -> Result<BtcHeaderIndex, Error> {
        match self.client.confirmed_index(None).await? {
            Some(confirmed_index) => {
                info!(
                    "[ChainX|{}_confirmed_index] Height #{}, Hash: {:?}",
                    block_chain_type,
                    confirmed_index.height,
                    hash_rev(confirmed_index.hash)
                );
                Ok(confirmed_index)
            }
            None => {
                // only use for the initialized confirmed index of the ChainX network.
                let genesis: (BtcBlockHeader, u32) = self.client.genesis_info(None).await?;
                let confirmed_index = BtcHeaderIndex {
                    hash: genesis.0.hash(),
                    height: genesis.1,
                };
                info!(
                    "[ChainX|btc_confirmed_index] (From genesis) Height #{}, Hash: {:?}",
                    confirmed_index.height,
                    hash_rev(confirmed_index.hash)
                );
                Ok(confirmed_index)
            }
        }
    }

    pub async fn chain_block_hash_for(&self, height: u32, block_chain_type: &str) -> Result<Vec<H256>, Error> {
        let hashes = self.client.block_hash_for(height, None).await?;
        info!(
            "[ChainX|{}_block_hash_for] Height #{}, Hashes: {:?}",
            block_chain_type,
            height,
            hashes
                .iter()
                .map(|hash| hash_rev(*hash))
                .collect::<Vec<_>>()
        );
        Ok(hashes)
    }

    pub async fn chain_block_header(
        &self,
        block_hash: &H256,
    ) -> Result<Option<BtcHeaderInfo>, Error> {
        if let Some(header) = time::timeout(
            Duration::from_secs(self.timeout),
            self.client.headers(block_hash, None),
        )
        .await??
        {
            info!(
                "[ChainX|btc_block_header] Height #{}, Header: {:?}",
                header.height, header.header,
            );
            Ok(Some(header))
        } else {
            Ok(None)
        }
    }

    pub async fn btc_tx_state(&self, tx_hash: &H256) -> Result<Option<BtcTxState>, Error> {
        if let Some(state) = time::timeout(
            Duration::from_secs(self.timeout),
            self.client.states(tx_hash, None),
        )
        .await??
        {
            info!(
                "[ChainX|tx_state] Transaction #{}, State: {:?}",
                tx_hash, state,
            );
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub async fn btc_best_block_header(&self) -> Result<Option<BtcHeaderInfo>, Error> {
        let best_index = self.chain_best_index("Bitcoin").await?;
        self.chain_block_header(&best_index.hash).await
    }

    pub async fn btc_withdrawal_proposal(
        &self,
    ) -> Result<Option<BtcWithdrawalProposal<AccountId>>, Error> {
        let withdrawal_proposal: Option<BtcWithdrawalProposal<AccountId>> =
            self.client.withdrawal_proposal(None).await?;
        if let Some(ref withdrawal_proposal) = withdrawal_proposal {
            info!(
                "[ChainX|btc_withdrawal_proposal] BTC Withdrawal Proposal: {:?}",
                withdrawal_proposal
            );
        }
        Ok(withdrawal_proposal)
    }

    pub async fn btc_pending_deposits<T: AsRef<[u8]>>(
        &self,
        outer_address: T,
    ) -> Result<Vec<BtcDepositCache>, Error> {
        let outer_address = outer_address.as_ref();
        let deposit_cache: Vec<BtcDepositCache> =
            self.client.pending_deposits(outer_address, None).await?;
        info!(
            "[ChainX|btc_pending_deposits] BTC Address `{}` ==> BTC Deposit Cache: {:?}",
            hex::encode(outer_address),
            deposit_cache
        );
        Ok(deposit_cache)
    }

    pub async fn chain_genesis_info(&self, block_chain_type: &str) -> Result<(BtcBlockHeader, u32), Error> {
        let genesis: (BtcBlockHeader, u32) = self.client.genesis_info(None).await?;
        info!(
            "[ChainX|chain_genesis_info] {} Genesis Block Height #{} ({:?})",
            block_chain_type,
            genesis.1,
            hash_rev(genesis.0.hash())
        );
        Ok(genesis)
    }

    // pub async fn transfer(
    //     &self,
    //     signer: &ChainXPairSigner,
    //     dest: &Address,
    //     amount: Balance,
    // ) -> Result<(), Error> {
    //     info!(
    //         "[ChainX|transfer] From: {:?}, To: {:?}, Amount: {}",
    //         signer.account_id(),
    //         dest,
    //         amount,
    //     );
    //     let ext: ExtrinsicSuccess<ChainXNodeRuntime> =
    //         self.client.transfer(signer, dest, amount).await?;
    //     info!(
    //         "[ChainX|transfer] Extrinsic Block Hash: {:?}, Extrinsic Hash: {:?}",
    //         ext.block, ext.extrinsic
    //     );
    //     if let Some(transfer_event) = ext.transfer()? {
    //         info!("[ChainX|transfer] Event: {:?}", transfer_event);
    //         Ok(())
    //     } else {
    //         error!("[ChainX|transfer] No Transfer Event");
    //         Err(Error::Other("Cannot find `Transfer` event".into()))
    //     }
    // }

    pub async fn push_btc_header(
        &self,
        signer: &ChainXPairSigner,
        header: &BtcBlockHeader,
    ) -> Result<(), Error> {
        info!(
            "[ChainX|push_btc_header] Btc Header Hash: {:?}",
            hash_rev(header.hash())
        );

        let header = serialize(header).take();
        let ext: H256 = time::timeout(
            Duration::from_secs(self.timeout),
            self.client.push_header(signer, &header),
        )
        .await??;
        info!("[ChainX|push_btc_header]  Extrinsic Hash: {:?}", ext);
        // info!(
        //     "[ChainX|push_btc_header] Extrinsic Block Hash: {:?}, Extrinsic Hash: {:?}",
        //     ext.block, ext.extrinsic
        // );
        time::sleep(Duration::from_secs(60)).await; /*Cause we cannot ensure extrinsic packaged.*/
        Ok(())
        // if let Some(push_header_event) = ext.push_header()? {
        //     info!("[ChainX|push_btc_header] Event: {:?}", push_header_event);
        //     Ok(())
        // } else {
        //     error!("[ChainX|push_btc_header] No PushHeader Event");
        //     Err(Error::Other("Cannot find `PushHeader` event".into()))
        // }
    }

    // pub async fn push_btc_transaction(
    //     &self,
    //     signer: &ChainXPairSigner,
    //     tx: &BtcTransaction,
    //     relayed_info: &BtcRelayedTxInfo,
    //     prev_tx: &Option<BtcTransaction>,
    // ) -> Result<(), Error> {
    //     let tx_hash = hash_rev(tx.hash());
    //     let prev_tx_hash = prev_tx.as_ref().map(|prev_tx| hash_rev(prev_tx.hash()));
    //     let block_hash = hash_rev(relayed_info.block_hash);
    //     let merkle_proof = serialize(&relayed_info.merkle_proof);
    //     info!(
    //         "[ChainX|push_btc_transaction] Tx: {:?}, Prev Tx: {:?}, Block: {:?}, Merkle Proof: {:?}",
    //         tx_hash, prev_tx_hash, block_hash, merkle_proof
    //     );
    //
    //     let tx = serialize(tx).take();
    //     let prev_tx = prev_tx.as_ref().map(|prev_tx| serialize(prev_tx).take());
    //     let ext: ExtrinsicSuccess<ChainXNodeRuntime> = time::timeout(
    //         Duration::from_secs(self.timeout),
    //         self.client
    //             .push_transaction_and_watch(signer, &tx, relayed_info, &prev_tx),
    //     )
    //     .await??;
    //     info!(
    //         "[ChainX|push_btc_transaction] Extrinsic Block Hash: {:?}, Extrinsic Hash: {:?}",
    //         ext.block, ext.extrinsic,
    //     );
    //     if let Some(push_tx_event) = ext.push_transaction()? {
    //         info!("[ChainX|push_btc_transaction] Event: {:?}", push_tx_event);
    //         Ok(())
    //     } else {
    //         error!("[ChainX|push_btc_transaction] No PushTransaction Event");
    //         Err(Error::Other("Cannot find `PushTransaction` event".into()))
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use sp_core::{crypto::DEV_PHRASE, Pair as _};
    use sp_runtime::traits::{IdentifyAccount, Verify};
    use subxt::Runtime;

    use super::*;
    use crate::runtime::ChainXPair;
    use light_bitcoin::primitives::h256;

    // use your own chainx node config.
    const CHAINX_WS_URL: &str = "ws://127.0.0.1:8087";
    const TIMEOUT: u64 = 15;

    /// Generate an account ID from seed.
    fn get_account_id_from_seed(seed: &str) -> AccountId {
        let pair = ChainXPair::from_string(&format!("//{}", seed), None)
            .expect("static values are valid; qed");
        <<ChainXNodeRuntime as Runtime>::Signature as Verify>::Signer::from(pair.public())
            .into_account()
    }

    #[test]
    fn test_account() {
        let alice = get_account_id_from_seed("Alice");
        println!("Alice = {:?}, {}", alice, alice);
        let bob = get_account_id_from_seed("Bob");
        println!("Bob = {:?}, {}", bob, bob);
        let charlie = get_account_id_from_seed("Charlie");
        println!("Charlie = {:?}, {}", charlie, charlie);

        // xgatewaycommon_bitcoinGenerateTrusteeSessionInfo
        let hot_addr = "3Cg16oUAzxj5EzpaHX6HHJUpJnuctEb9L8"
            .parse::<BtcAddress>()
            .unwrap();
        let cold_addr = "3H7Gu3KsGoa8UbqrY5hfA2S3PVsPwzur3t"
            .parse::<BtcAddress>()
            .unwrap();
        println!("hot: {:?}, cold: {:?}", hot_addr, cold_addr);
    }

    #[test]
    fn test_seed() {
        let pair = ChainXPair::from_string(&format!("{}//Alice", DEV_PHRASE), None).unwrap();
        let public = pair.public();
        println!("public: {:?}", sp_core::H256::from(public.0));
    }

    #[ignore]
    // #[cfg(any(feature = "dogecoin", feature = "bitcoin"))]
    #[tokio::test]
    async fn test_chainx() {
        let chainx = ChainX::new(CHAINX_WS_URL, TIMEOUT).await.unwrap();

        let _btc_withdrawal_proposal = chainx.btc_withdrawal_proposal().await.unwrap();

        let alice = get_account_id_from_seed("Alice");
        let _free_pcx = chainx.free_pcx_balance(&alice).await.unwrap();

        let index = chainx.chain_best_index("Bitcoin").await.unwrap();
        println!(
            "Best Index: height {:?}, hash {:?}",
            index.height,
            hash_rev(index.hash)
        );
        // Height #576576, Hash: 0x82185fa131e2e2e1ddf05125a0950271b088eb8df52117000000000000000000
        let index = chainx.chain_confirmed_index("Bitcoin").await.unwrap();
        println!(
            "Confirmed Index: height {:?} hash {:?}",
            index.height,
            hash_rev(index.hash)
        );
        let hashes = chainx.chain_block_hash_for(1863320, "Bitcoin").await.unwrap();
        println!(
            "Block Hash For: {:?}",
            hashes.into_iter().map(hash_rev).collect::<Vec<_>>()
        );
        // Height #576576, Hash: 0x82185fa131e2e2e1ddf05125a0950271b088eb8df52117000000000000000000
        let header = chainx.btc_best_block_header().await.unwrap();
        println!("Best Block Header: {:?}", header);
        // Height #576576, Header: BlockHeader { version: 536870912, previous_header_hash: 0x0000000000000000000a4adf6c5192128535d4dcb56cfb5753755f8d392b26bf, merkle_root_hash: 0x1d21e60acb0b12e5cfd3f775edb647f982a2d666f9886b2f61ea5e72577b0f5e, time: 1558168296, bits: Compact(388627269), nonce: 1439505020 }
        let btc_genesis = chainx.chain_genesis_info("Bitcoin").await.unwrap();
        println!("Bitcoin Genesis: {:?}", btc_genesis);
        // Height #576576, Header: BlockHeader { version: 536870912, previous_header_hash: 0x0000000000000000000a4adf6c5192128535d4dcb56cfb5753755f8d392b26bf, merkle_root_hash: 0x1d21e60acb0b12e5cfd3f775edb647f982a2d666f9886b2f61ea5e72577b0f5e, time: 1558168296, bits: Compact(388627269), nonce: 1439505020 }
        let tx_state = chainx
            .btc_tx_state(&h256(
                "08b5673864d4f639a8b2006bc4fac18b92f3c7a5fd4e31eeb1813deff66dde8c",
            ))
            .await
            .unwrap()
            .unwrap();
        println!(
            "Tx Hash: {:?}",
            h256("08b5673864d4f639a8b2006bc4fac18b92f3c7a5fd4e31eeb1813deff66dde8c")
        );
        println!("Transaction State: {:?}", tx_state);
        // Transaction State: BtcTxState { tx_type: Deposit, result: Success }
    }

    // #[ignore]
    // #[tokio::test]
    // async fn test_transfer() {
    //     let chainx = ChainX::new(CHAINX_WS_URL, TIMEOUT).await.unwrap();
    //
    //     let alice = get_account_id_from_seed("Alice");
    //     let bob = get_account_id_from_seed("Bob");
    //
    //     let alice_before = chainx.free_pcx_balance(&alice).await.unwrap();
    //     let bob_before = chainx.free_pcx_balance(&bob).await.unwrap();
    //     println!("Alice = {}, Bob = {}", alice_before, bob_before);
    //
    //     // transfer (Alice ==> Bob)
    //     let pair = ChainXPair::from_string(&format!("{}//Alice", DEV_PHRASE), None).unwrap();
    //     let signer = ChainXPairSigner::new(pair);
    //     let amount = 10_000;
    //     let dest = get_account_id_from_seed("Bob").into();
    //     chainx.transfer(&signer, &dest, amount).await.unwrap();
    //
    //     let alice_after = chainx.free_pcx_balance(&alice).await.unwrap();
    //     let bob_after = chainx.free_pcx_balance(&bob).await.unwrap();
    //     println!("Alice = {}, Bob = {}", alice_after, bob_after);
    //
    //     assert!(alice_before - amount >= alice_after);
    //     assert_eq!(bob_before + amount, bob_after);
    // }
}
