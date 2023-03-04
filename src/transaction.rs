use ethers::types::{Address, U256};

pub trait Transactionable: Sized {
    fn calldata(&self) -> anyhow::Result<Vec<u8>>;
    fn to(&self) -> Address;
    fn value(&self) -> U256;
}
