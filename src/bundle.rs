use crate::encoding::{bytes_to_hex_string, hex_string_to_bytes};
use crate::transaction::Transactionable;
use ethers::types::U256;
use safe_client_gateway::common::models::data_decoded::Operation;
use std::ops::Add;

/// The selector for the Safe transaction data
/// hex encoded: 0x8d80ff0a
const SELECTOR_BYTES: &[u8] = &[141, 128, 255, 10];

#[derive(Debug, Clone)]
pub struct Bundle<T: Transactionable> {
    pub transactions: Vec<T>,
    calldata: Vec<u8>,
    value: U256,
}

impl<T: Transactionable> Bundle<T> {
    pub fn new(transactions: Vec<(T, Operation)>) -> anyhow::Result<Self> {
        let (encoded, value): (Vec<String>, Vec<U256>) = transactions
            .iter()
            .map(|(tx, op)| {
                // 2 byte operation
                let encoded_operation = bytes_to_hex_string(vec![match op {
                    Operation::CALL => 0,
                    Operation::DELEGATE => 1,
                }]);

                // hard code value as 0 for nows 32 bytes
                let encoded_value = pad(tx.value());

                // returns 20 byte address
                let encoded_address = bytes_to_hex_string(tx.to().as_bytes());
                let encoded_data = bytes_to_hex_string(tx.calldata().unwrap());

                // 2 char = 1 byte
                let data_length = pad(U256::from(encoded_data.len() / 2));

                let mut calldata = String::new();
                calldata.push_str(&encoded_operation);
                calldata.push_str(&encoded_address);
                calldata.push_str(&encoded_value);
                calldata.push_str(&data_length);
                calldata.push_str(&encoded_data);

                (calldata, tx.value())
            })
            .unzip();

        let encoded = ethers::abi::encode(&[ethers::abi::Token::Bytes(hex_string_to_bytes(
            &encoded.join(""),
        )?)]);

        Ok(Self {
            calldata: vec![SELECTOR_BYTES, &encoded].concat(),
            transactions: transactions.into_iter().map(|(tx, _)| tx).collect(),
            value: value
                .into_iter()
                .fold(U256::zero(), |acc, value| acc.add(value)),
        })
    }
}

fn pad(value: U256) -> String {
    let unpadded_hex = format!("{:x}", value);
    String::from("0").repeat(64 - unpadded_hex.len()) + &unpadded_hex
}

impl<T: Transactionable> Transactionable for Bundle<T> {
    fn calldata(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.calldata.clone())
    }

    fn to(&self) -> ethers::types::Address {
        *crate::constants::MULTISEND_ADDRESS
    }

    fn value(&self) -> U256 {
        self.value
    }
}

#[cfg(test)]
#[test]
fn test_encoding() {
    // hard code value as 0 for nows

    use crate::encoding::bytes_to_hex_string;
    let encoded_value = String::from("0").repeat(64);

    let encoded_address = bytes_to_hex_string(ethers::types::Address::zero().as_bytes());

    let encoded_operation = bytes_to_hex_string(vec![0]);

    let len = format!("{:x}", 6000);

    let num = U256::from(22);

    println!("encoded_value: {encoded_value}");
    println!("encoded_address: {encoded_address}");
    println!("encoded_operation: {encoded_operation}");
    println!("len: {len}");

    assert_eq!(
        pad(num),
        "0000000000000000000000000000000000000000000000000000000000000016",
    );
    assert_eq!(encoded_value.len(), 64);
    assert_eq!(encoded_address.len(), 40);
    assert_eq!(encoded_operation.len(), 2);
    assert_eq!(len, String::from("1770"));
}
