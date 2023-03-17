use super::transaction::Transactionable;
use crate::constants::{DOMAIN_TYPE_HASH, PAYLOAD_TYPE_HASH};
use crate::encoding::bytes_to_hex_string;
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
use safe_client_gateway::common::models::data_decoded::Operation;
use safe_client_gateway::routes::transactions::models::details::{
    DetailedExecutionInfo, TransactionData, TransactionDetails,
};
use tracing::{debug, info};

abigen!(GnosisSafe, "abi/gnosis_safe.json",);

#[derive(Debug, Clone)]
pub struct SignedSafePayload<T: Transactionable> {
    pub payload: SafeTransaction<T>,
    pub signature: Signature,
    pub sender: Address,
}

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

impl<T: Transactionable> SafeTransaction<T> {
    pub async fn new(
        tx: T,
        chain_id: u64,
        safe_address: Address,
        operation: Operation,
        nonce: Option<U256>,
        safe_tx_gas: Option<U256>,
        base_gas: Option<U256>,
        gas_price: Option<U256>,
        gas_token: Option<Address>,
        refund_receiver: Option<Address>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            tx,
            chain_id,
            safe_address,
            safe_tx_gas: safe_tx_gas.unwrap_or(U256::zero()),
            base_gas: base_gas.unwrap_or(U256::zero()),
            gas_price: gas_price.unwrap_or(U256::zero()),
            gas_token: gas_token.unwrap_or(Address::zero()),
            refund_receiver: refund_receiver.unwrap_or(Address::zero()),
            nonce: nonce.unwrap_or({
                debug!("No nonce provided, getting a new nonce from contract");
                U256::from(
                    crate::api::safes(chain_id, safe_address)
                        .await?
                        .safe_config
                        .nonce,
                )
            }),
            operation,
        })
    }

    /// returns the first pending transactions that matches this calldata
    pub async fn match_calldata(
        tx: &T,
        safe_address: Address,
        chain_id: u64,
    ) -> anyhow::Result<Option<TransactionDetails>> {
        let calldata = tx.calldata()?;
        let tx_details = super::api::queued_details(chain_id, safe_address).await?;
        Ok(tx_details.into_iter().find(|transaction_details| {
            let TransactionDetails {
                tx_data: Some(TransactionData {
                    hex_data: Some(data)
                    ,..
                })
                ,..
            } = transaction_details else {
                return false;
            };

            *data == "0x".to_owned() + &bytes_to_hex_string(&calldata)
        }))
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
}

impl<T: Transactionable> SignedSafePayload<T> {
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
        } = self.payload;

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

    pub async fn propose(self) -> anyhow::Result<TransactionDetails> {
        super::api::propose(self).await
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
