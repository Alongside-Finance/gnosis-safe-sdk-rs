use crate::encoding::{bytes_to_hex_string, hex_string_to_bytes};
use crate::transaction::Transactionable;
use crate::types::Bundle;
use ethers::types::U256;
use safe_client_gateway::common::models::data_decoded::Operation;

/// The selector for the Safe transaction data
/// hex encoded: 0x8d80ff0a
const SELECTOR_BYTES: &[u8] = &[141, 128, 255, 10];

impl<T: Transactionable> Bundle<T> {
    pub fn new(transactions: Vec<(T, Operation)>) -> anyhow::Result<Self> {
        let calldatas: Vec<String> = transactions
            .iter()
            .map(|(tx, op)| {
                // 2 byte operation
                let encoded_operation = bytes_to_hex_string(vec![match op {
                    Operation::CALL => 0,
                    Operation::DELEGATE => 1,
                }]);

                // hard code value as 0 for nows 32 bytes
                let encoded_value = String::from("0").repeat(64);

                // returns 20 byte address
                let encoded_address = bytes_to_hex_string(tx.to().as_bytes());

                let encoded_data = bytes_to_hex_string(tx.calldata().unwrap());

                // 2 char = 1 byte
                let unpadded_data_length = format!("{:x}", encoded_data.len() / 2);

                // 32 bytes
                let padded_data_length = String::from("0").repeat(64 - unpadded_data_length.len())
                    + &unpadded_data_length;

                let mut calldata = String::new();
                calldata.push_str(&encoded_operation);
                calldata.push_str(&encoded_address);
                calldata.push_str(&encoded_value);
                calldata.push_str(&padded_data_length);
                calldata.push_str(&encoded_data);

                calldata
            })
            .collect();

        let encoded = ethers::abi::encode(&[ethers::abi::Token::Bytes(hex_string_to_bytes(
            &calldatas.join(""),
        )?)]);

        Ok(Self {
            calldata: vec![SELECTOR_BYTES, &encoded].concat(),
            transactions: transactions.into_iter().map(|(tx, _)| tx).collect(),
        })
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

    println!("encoded_value: {encoded_value}");
    println!("encoded_address: {encoded_address}");
    println!("encoded_operation: {encoded_operation}");
    println!("len: {len}");

    assert_eq!(encoded_value.len(), 64);
    assert_eq!(encoded_address.len(), 40);
    assert_eq!(encoded_operation.len(), 2);
    assert_eq!(len, String::from("1770"));
}

impl<T: Transactionable> Transactionable for Bundle<T> {
    fn calldata(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.calldata.clone())
    }

    fn to(&self) -> ethers::types::Address {
        *crate::constants::MULTISEND_ADDRESS
    }

    // 0 value for now, in future can calc at bundle creation time
    // todo!()
    fn value(&self) -> U256 {
        U256::zero()
    }
}
