extern crate "rustc-serialize" as serialize;

use serialize::base64::{ToBase64,STANDARD};

pub fn to_base64 (bytes: &[u8]) -> String {
    return bytes.to_base64(STANDARD);
}

pub fn fixed_xor (bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    return bytes1.iter()
        .zip(bytes2.iter())
        .map(|(&a, &b)| { a ^ b })
        .collect();
}
