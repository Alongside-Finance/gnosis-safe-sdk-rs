use super::transaction::Transactionable;
use crate::bundle::Bundle;
use crate::constants::{DOMAIN_TYPE_HASH, PAYLOAD_TYPE_HASH};
use ethers::prelude::abigen;
use ethers::prelude::builders::ContractCall;
use ethers::providers::Middleware;
use ethers::types::Signature;
use ethers::types::{Address, U256};
use ethers::utils::keccak256;
use ethers::{
    abi,
    abi::Token,
    types::transaction::eip712::{EIP712Domain, Eip712, Eip712Error},
};
use itertools::Itertools;
use safe_client_gateway::common::models::data_decoded::Operation;
use safe_client_gateway::routes::transactions::models::details::{
    DetailedExecutionInfo, TransactionDetails,
};
use tracing::info;

abigen!(GnosisSafe, "abi/gnosis_safe.json",);

#[derive(Debug, Clone)]
pub struct SignedSafePayload<T: Transactionable> {
    pub payload: SafeTransaction<T>,
    pub signature: Signature,
    pub sender: Address,
}

/// defaults to a CALL operation
/// Defaults to getting the nonce from the contract
#[derive(Debug, Clone)]
pub struct SafeTransactionBuilder<T: Transactionable> {
    pub tx: T,
    pub chain_id: u64,
    pub safe_address: Address,
    pub safe_tx_gas: Option<U256>,
    pub base_gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub gas_token: Option<Address>,
    pub refund_receiver: Option<Address>,
    pub nonce: Option<U256>,
    pub operation: Option<Operation>,
}

#[derive(Debug, Clone, Copy)]
pub struct SafeTransaction<T: Transactionable> {
    pub tx: T,
    pub safe_address: Address,
    pub chain_id: u64,
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
    pub nonce: U256,
    pub operation: Operation,
}

pub fn attempt_extract_nonce(tx: &TransactionDetails) -> Option<u64> {
    match tx.detailed_execution_info.clone() {
        Some(DetailedExecutionInfo::Multisig(info)) => Some(info.nonce),
        _ => None,
    }
}

impl<T: Transactionable> Eip712 for SafeTransaction<T> {
    type Error = Eip712Error;
    fn domain_separator(&self) -> Result<[u8; 32], Self::Error> {
        let encoded = abi::encode(&[
            Token::FixedBytes(DOMAIN_TYPE_HASH.clone()),
            Token::Uint(U256::from(self.chain_id)),
            Token::Address(self.safe_address),
        ]);

        Ok(keccak256(encoded))
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        PAYLOAD_TYPE_HASH
            .clone()
            .try_into()
            .map_err(|_| Eip712Error::Message("Type Hash Failed".to_string()))
    }

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(EIP712Domain {
            name: None,
            version: None,
            chain_id: Some(U256::from(self.chain_id)),
            verifying_contract: Some(self.safe_address),
            salt: None,
        })
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        Ok(keccak256(abi::encode(&[
            Token::FixedBytes(PAYLOAD_TYPE_HASH.clone()),
            Token::Address(self.tx.to()),
            Token::Uint(self.tx.value()),
            Token::FixedBytes(
                keccak256(
                    self.tx
                        .calldata()
                        .map_err(|_| Eip712Error::FailedToEncodeStruct)?,
                )
                .to_vec(),
            ), // see EIP-712, bytes are hashed
            Token::Uint(match self.operation {
                Operation::CALL => U256::from(0),
                Operation::DELEGATE => U256::from(1),
            }),
            Token::Uint(self.safe_tx_gas),
            Token::Uint(self.base_gas),
            Token::Uint(self.gas_price),
            Token::Address(self.gas_token),
            Token::Address(self.refund_receiver),
            Token::Uint(self.nonce),
        ])))
    }
}

impl<T: Transactionable> SafeTransactionBuilder<T> {
    pub async fn build(self) -> anyhow::Result<SafeTransaction<T>> {
        let nonce = match self.nonce {
            Some(nonce) => nonce,
            None => self.next_nonce().await?,
        };
        Ok(SafeTransaction {
            tx: self.tx,
            chain_id: self.chain_id,
            safe_address: self.safe_address,
            safe_tx_gas: self.safe_tx_gas.unwrap_or(U256::zero()),
            base_gas: self.base_gas.unwrap_or(U256::zero()),
            gas_price: self.gas_price.unwrap_or(U256::zero()),
            gas_token: self.gas_token.unwrap_or(Address::zero()),
            refund_receiver: self.refund_receiver.unwrap_or(Address::zero()),
            nonce: nonce,
            operation: self.operation.unwrap_or(Operation::CALL),
        })
    }

    pub fn new(tx: T, chain_id: u64, safe_address: Address) -> Self {
        Self {
            tx,
            chain_id,
            safe_address,
            safe_tx_gas: None,
            base_gas: None,
            gas_price: None,
            gas_token: None,
            refund_receiver: None,
            nonce: None,
            operation: None,
        }
    }

    /// Sets the operation as delegate for the bundle
    pub fn from_bundle(
        bundle: Bundle<T>,
        chain_id: u64,
        safe_address: Address,
    ) -> SafeTransactionBuilder<Bundle<T>> {
        SafeTransactionBuilder::new(bundle, chain_id, safe_address).operation(Operation::DELEGATE)
    }

    pub async fn next_nonce(&self) -> anyhow::Result<U256> {
        Ok(U256::from(
            crate::api::safes(self.chain_id, self.safe_address)
                .await?
                .safe_config
                .nonce,
        ))
    }

    pub fn safe_tx_gas(mut self, safe_tx_gas: U256) -> Self {
        self.safe_tx_gas = Some(safe_tx_gas);
        self
    }

    pub fn base_gas(mut self, base_gas: U256) -> Self {
        self.base_gas = Some(base_gas);
        self
    }

    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    pub fn gas_token(mut self, gas_token: Address) -> Self {
        self.gas_token = Some(gas_token);
        self
    }

    pub fn refund_receiver(mut self, refund_receiver: Address) -> Self {
        self.refund_receiver = Some(refund_receiver);
        self
    }

    pub fn nonce(mut self, nonce: U256) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn operation(mut self, operation: Operation) -> Self {
        self.operation = Some(operation);
        self
    }
}

impl<T: Transactionable> SafeTransaction<T> {
    pub async fn new(
        tx: T,
        chain_id: u64,
        safe_address: Address,
        operation: Operation,
        nonce: U256,
        safe_tx_gas: U256,
        base_gas: U256,
        gas_price: U256,
        gas_token: Address,
        refund_receiver: Address,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            tx,
            chain_id,
            safe_address,
            safe_tx_gas: safe_tx_gas,
            base_gas: base_gas,
            gas_price: gas_price,
            gas_token: gas_token,
            refund_receiver: refund_receiver,
            nonce,
            operation,
        })
    }

    pub fn sort_and_join_sigs(sigs: &Vec<(Address, String)>) -> String {
        let mut cloned = sigs.clone();
        cloned.sort_by(|a, b| a.0.cmp(&b.0));
        cloned
            .into_iter()
            .map(|(_, sig)| sig.replace("0x", ""))
            .join("")
    }

    pub async fn sign_safe_tx<S: 'static + ethers::signers::Signer>(
        self,
        signer: &S,
    ) -> anyhow::Result<SignedSafePayload<T>> {
        info!("Signing Safe Transaction");
        Ok(SignedSafePayload {
            signature: signer.sign_typed_data(&self).await?,
            payload: self,
            sender: signer.address(),
        })
    }

    pub fn execute_contract_call<M: Middleware>(
        self,
        signatures: String,
        client: &std::sync::Arc<M>,
    ) -> anyhow::Result<ContractCall<M, bool>> {
        let SafeTransaction {
            tx,
            safe_address,
            safe_tx_gas,
            base_gas,
            gas_price,
            gas_token,
            refund_receiver,
            operation,
            ..
        } = self;

        let instance = GnosisSafe::new(safe_address, client.clone());

        let call: ethers::contract::builders::ContractCall<_, _> = instance.exec_transaction(
            tx.to(),
            tx.value(),
            tx.calldata()?.into(),
            operation as u8,
            safe_tx_gas,
            base_gas,
            gas_price,
            gas_token,
            refund_receiver,
            crate::encoding::hex_string_to_bytes(&signatures)?.into(),
        );

        Ok(call)
    }
}

#[cfg(test)]
#[test]
fn test_hashing() {
    use crate::encoding::bytes_to_hex_string;
    use ethers::types::{Address, H256, U256};

    #[derive(Clone)]
    struct Test {
        to: Address,
        value: U256,
    }

    impl Transactionable for Test {
        fn calldata(&self) -> anyhow::Result<Vec<u8>> {
            Ok(H256::zero().as_bytes().to_vec())
        }

        fn to(&self) -> Address {
            self.to
        }

        fn value(&self) -> U256 {
            self.value
        }
    }

    let test = Test {
        to: "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap(),
        value: U256::zero(),
    };

    let payload = SafeTransaction {
        tx: test,
        safe_address: "0x783c330A7A4968A08ce100A16ac27Ff2cCfAEbdf"
            .parse()
            .unwrap(),
        chain_id: 1,
        safe_tx_gas: U256::zero(),
        base_gas: U256::zero(),
        gas_price: U256::zero(),
        gas_token: "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap(),
        refund_receiver: "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap(),
        nonce: U256::zero(),
        operation: safe_client_gateway::common::models::data_decoded::Operation::CALL,
    };

    let hash = payload.encode_eip712().unwrap();
    let domain_hash = payload.domain_separator().unwrap();
    let type_hash = SafeTransaction::<Test>::type_hash().unwrap();
    let _struct_hash = payload.struct_hash().unwrap();

    assert_eq!(
        bytes_to_hex_string(domain_hash),
        "9e77d02315090a7bc2b29a1707fd72188fa1bd7347c05a3a9a02981888cf847d"
    );

    assert_eq!(
        bytes_to_hex_string(type_hash),
        "bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
    );

    assert_eq!(
        bytes_to_hex_string(hash),
        "0f7b372b07f04519dfa3c6e54766a16719474099fe10705fd5cd5567403134cd"
    );
}
