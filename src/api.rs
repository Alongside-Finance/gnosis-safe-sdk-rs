use crate::encoding::bytes_to_hex_string;
use crate::safe::SignedSafePayload;
use crate::transaction::Transactionable;
use core::fmt::Debug;
use ethers::types::transaction::eip712::Eip712;
use ethers::types::Address;
use ethers::utils::to_checksum;
use lazy_static::lazy_static;
use reqwest::header::{HeaderName, HeaderValue};
use safe_client_gateway::common::models::data_decoded::Operation;
use safe_client_gateway::common::models::page::Page;
use safe_client_gateway::routes::{
    safes::models::SafeState,
    transactions::models::{
        details::TransactionDetails,
        summary::{TransactionListItem, TransactionSummary},
    },
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::debug;

const BASE_URL: &str = "https://safe-client.safe.global/v1/chains";

lazy_static! {
    static ref CLIENT: reqwest::Client = reqwest::ClientBuilder::new()
        .default_headers({
            reqwest::header::HeaderMap::from_iter(
                [("cache-control", "no-cache")]
                    .iter()
                    .map(|(k, v)| (HeaderName::from_static(k), HeaderValue::from_static(v))),
            )
        })
        .build()
        .unwrap();
}

pub(super) fn make_route(url: &str, route: &[&str]) -> String {
    format!("{}/{}", url, route.join("/"))
}

async fn friendly_handle<T>(response: reqwest::Response) -> anyhow::Result<T>
where
    T: Debug + DeserializeOwned,
{
    let pretty_response = format!("{response:#?}");
    if response.status() != reqwest::StatusCode::OK {
        let text = response.text().await?;
        anyhow::bail!("arbnormal status code\n{pretty_response}\nGot body\n{text:#?}",);
    }
    let text = response.text().await?;
    match serde_json::from_str::<T>(&text) {
        Err(e) => {
            anyhow::bail!("failed to parse response: {}\n{text:#?}", e);
        }
        Ok(x) => Ok(x),
    }
}

async fn friendly_execute<T>(request: reqwest::RequestBuilder) -> anyhow::Result<T>
where
    T: Debug + DeserializeOwned,
{
    friendly_handle(request.send().await?).await
}

fn api_url(chain_id: u64, route: &[&str]) -> String {
    let chain_id_string = chain_id.to_string();
    let mut chain_id_and_route = vec![chain_id_string.as_ref()];
    chain_id_and_route.extend_from_slice(route);
    make_route(BASE_URL, &chain_id_and_route)
}

pub async fn safes(chain_id: u64, address: Address) -> anyhow::Result<SafeState> {
    let checksummed_address = ethers::core::utils::to_checksum(&address, None);
    debug!("getting safe {}", checksummed_address);
    friendly_execute(CLIENT.get(&api_url(chain_id, &["safes", &checksummed_address]))).await
}

pub async fn queued(chain_id: u64, address: Address) -> anyhow::Result<Vec<TransactionSummary>> {
    let checksummed_address = ethers::core::utils::to_checksum(&address, None);
    debug!("getting queue for safe {}", checksummed_address);
    let tx_summaries: Vec<TransactionSummary> =
        friendly_execute::<Page<TransactionListItem>>(CLIENT.get(&api_url(
            chain_id,
            &["safes", &checksummed_address, "transactions", "queued"],
        )))
        .await?
        .results
        .into_iter()
        .flat_map(|tli| match tli {
            TransactionListItem::Transaction { transaction, .. } => Some(transaction),
            _ => None,
        })
        .collect();
    debug!("received {} queued transactions", tx_summaries.len());
    Ok(tx_summaries)
}

async fn transaction_details(
    chain_id: u64,
    details_id: &str,
) -> anyhow::Result<TransactionDetails> {
    debug!("getting details for transaction {}", &details_id);
    friendly_execute(CLIENT.get(&api_url(chain_id, &["transactions", details_id]))).await
}

pub async fn queued_details(
    chain_id: u64,
    address: Address,
) -> anyhow::Result<Vec<TransactionDetails>> {
    let all_queued = queued(chain_id, address).await?;
    futures::future::try_join_all(
        all_queued
            .iter()
            .map(|tx| transaction_details(chain_id, &tx.id)),
    )
    .await
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
// Addresses are not mapped to AddressEx as this is a request body that is forwarded to the core services
pub struct MultisigTransactionRequest {
    pub to: String,
    pub value: String,
    pub data: Option<String>,
    pub nonce: String,
    pub operation: Operation,
    pub safe_tx_gas: String,
    pub base_gas: String,
    pub gas_price: String,
    pub gas_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_receiver: Option<String>,
    pub safe_tx_hash: String,
    pub sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl<T: Transactionable> From<SignedSafePayload<T>> for MultisigTransactionRequest {
    /// consumes a signed transaction and returns a MultisigTransactionRequest
    fn from(
        SignedSafePayload {
            payload,
            signature,
            sender,
        }: SignedSafePayload<T>,
    ) -> Self {
        let hash = payload.encode_eip712().unwrap();
        let inner = payload.tx;
        Self {
            to: to_checksum(&inner.to(), None),
            // todo check encoding
            value: inner.value().to_string(),
            data: Option::Some("0x".to_owned() + &bytes_to_hex_string(inner.calldata().unwrap())),
            operation: payload.operation,
            safe_tx_gas: payload.safe_tx_gas.to_string(),
            base_gas: payload.base_gas.to_string(),
            gas_price: payload.gas_price.to_string(),
            gas_token: to_checksum(&payload.gas_token, None),
            refund_receiver: Some(to_checksum(&payload.refund_receiver, None)),
            nonce: payload.nonce.to_string(),
            signature: Option::Some("0x".to_owned() + &signature.to_string()),
            safe_tx_hash: "0x".to_owned() + &bytes_to_hex_string(hash),
            sender: to_checksum(&sender, None),
            origin: Option::None,
        }
    }
}

pub async fn propose<T: Transactionable>(
    chain_id: u64,
    address: Address,
    tx: SignedSafePayload<T>,
) -> anyhow::Result<TransactionDetails> {
    let checksummed_address = ethers::core::utils::to_checksum(&address, None);
    let tx = MultisigTransactionRequest::from(tx);
    friendly_execute(
        CLIENT
            .post(&api_url(
                chain_id,
                &["transactions", &checksummed_address, "propose"],
            ))
            .json(&tx),
    )
    .await
}
