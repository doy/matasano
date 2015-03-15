extern crate "rustc-serialize" as serialize;

use serialize::base64::{ToBase64,STANDARD};
use serialize::hex::FromHex;

pub fn hex_to_base64 (hex: &str) -> String {
    let bytes = match hex.from_hex() {
        Ok(b) => b,
        Err(e) => panic!("{}", e),
    };
    return bytes.to_base64(STANDARD);
}
