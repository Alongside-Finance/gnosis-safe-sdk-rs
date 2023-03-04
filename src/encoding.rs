pub fn hex_string_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(hex.replace("0x", ""))?)
}

pub fn bytes_to_hex_string<T: AsRef<[u8]>>(bytes: T) -> String {
    hex::encode(bytes)
}
