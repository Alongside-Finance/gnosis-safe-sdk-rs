use ethers::types::Address;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref MULTISEND_ADDRESS: Address = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"
        .parse()
        .unwrap();

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    pub static ref DOMAIN_TYPE_HASH: Vec<u8> = vec![
        71, 231, 149, 52, 162, 69, 149, 46, 139, 22, 137, 58, 51, 107, 133, 163, 217, 234, 159,
        168, 197, 115, 243, 216, 3, 175, 185, 42, 121, 70, 146, 24,
    ];

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    pub static ref PAYLOAD_TYPE_HASH: Vec<u8> = vec![
        187, 131, 16, 212, 134, 54, 141, 182, 189, 111, 132, 148, 2, 253, 215, 58, 213, 61, 49,
        107, 90, 75, 38, 68, 173, 110, 254, 15, 148, 18, 134, 216,
    ];
}
