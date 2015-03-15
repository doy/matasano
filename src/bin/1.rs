extern crate "rustc-serialize" as serialize;

use std::io::prelude::*;
use serialize::base64::{ToBase64,STANDARD};
use serialize::hex::FromHex;

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
        let hex = std::str::from_utf8(&buf[..len]).unwrap();
        let bytes = match hex.from_hex() {
            Ok(b) => b,
            Err(e) => panic!("{}", e),
        };
        let base64 = bytes.to_base64(STANDARD);
        print!("{}", base64);
    }
}
