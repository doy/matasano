extern crate "rustc-serialize" as serialize;

#[cfg(not(test))] use std::io::prelude::*;

use serialize::base64::{ToBase64,STANDARD};
use serialize::hex::FromHex;

fn hex_to_base64 (hex: &str) -> String {
    let bytes = match hex.from_hex() {
        Ok(b) => b,
        Err(e) => panic!("{}", e),
    };
    return bytes.to_base64(STANDARD);
}

#[cfg(not(test))]
fn main () {
    loop {
        let mut buf = [0; 6];
        let len = match std::io::stdin().read(&mut buf) {
            Ok(n) => n,
            Err(e) => panic!("{}", e),
        };
        if len == 0 {
            break;
        }
        print!("{}", hex_to_base64(std::str::from_utf8(&buf[..len]).unwrap()));
    }
}

#[test]
fn test_base64 () {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(hex_to_base64(hex), base64);
}
