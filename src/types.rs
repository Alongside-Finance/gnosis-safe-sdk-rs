use crate::transaction::Transactionable;
use ethers::types::U256;
use ethers::types::{Address, Signature};
use safe_client_gateway::common::models::data_decoded::Operation;

#[derive(Debug, Clone, Copy)]
pub struct SafeTransaction<T: Transactionable> {
    pub tx: T,
    pub safe_address: Address,
    pub chain_id: u64,
    /// u256::zero() for none
    pub safe_tx_gas: U256,
    /// u256::zero() for none
    pub base_gas: U256,
    /// u256::zero() for none
    pub gas_price: U256,
    /// zero address for none
    pub gas_token: Address,
    /// zero address for none
    pub refund_receiver: Address,
    pub nonce: U256,
    pub operation: Operation,
}

#[derive(Debug, Clone)]
pub struct SignedSafePayload<T: Transactionable> {
    pub payload: SafeTransaction<T>,
    pub signature: Signature,
    pub sender: Address,
}

#[derive(Debug, Clone)]
pub struct Bundle<T: Transactionable> {
    pub transactions: Vec<T>,
    pub calldata: Vec<u8>,
}
