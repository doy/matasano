extern crate "rustc-serialize" as serialize;

use serialize::base64::{ToBase64,STANDARD};
use serialize::hex::{FromHex,ToHex};

pub fn hex_to_base64 (hex: &str) -> String {
    let bytes = hex.from_hex().unwrap();
    return bytes.to_base64(STANDARD);
}

pub fn fixed_xor (str1: &str, str2: &str) -> String {
    let bytes1 = str1.from_hex().unwrap();
    let bytes2 = str2.from_hex().unwrap();
    return bytes1.iter()
        .zip(bytes2.iter())
        .map(|(&a, &b)| { a ^ b })
        .collect::<Vec<u8>>()
        .to_hex();
}
