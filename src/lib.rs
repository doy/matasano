extern crate "rustc-serialize" as serialize;

use std::ascii::AsciiExt;
use std::num::Float;

use serialize::base64::{ToBase64,STANDARD};

const ENGLISH_FREQUENCIES: [f64; 26] = [
    0.0812,
    0.0149,
    0.0271,
    0.0432,
    0.1202,
    0.0230,
    0.0203,
    0.0592,
    0.0731,
    0.0010,
    0.0069,
    0.0398,
    0.0261,
    0.0695,
    0.0768,
    0.0182,
    0.0011,
    0.0602,
    0.0628,
    0.0910,
    0.0288,
    0.0111,
    0.0209,
    0.0017,
    0.0211,
    0.0007,
];

pub fn to_base64 (bytes: &[u8]) -> String {
    return bytes.to_base64(STANDARD);
}

pub fn fixed_xor (bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    return bytes1.iter()
        .zip(bytes2.iter())
        .map(|(&a, &b)| { a ^ b })
        .collect();
}

pub fn crack_single_byte_xor (input: &[u8]) -> Vec<u8> {
    let (decrypted, _) = crack_single_byte_xor_with_confidence(input);
    return decrypted;
}

fn crack_single_byte_xor_with_confidence (input: &[u8]) -> (Vec<u8>, f64) {
    let mut min_diff = 100.0;
    let mut best_decrypted = vec![];
    for a in 0..256 {
        let decrypted = fixed_xor(
            input,
            &std::iter::repeat(a as u8)
                .take(input.len())
                .collect::<Vec<u8>>()[..]
        );
        if !decrypted.is_ascii() {
            continue;
        }
        if decrypted.iter().any(|&c| { c < 0x20 || c > 0x7E }) {
            continue;
        }
        let lowercase = decrypted.to_ascii_lowercase();
        let mut frequencies = [0; 26];
        let mut total_frequency = 0;
        for c in lowercase {
            if c >= 0x61 && c <= 0x7A {
                total_frequency += 1;
                frequencies[(c - 0x61) as usize] += 1;
            }
        }

        let mut total_diff = 0.0;
        for (&english, &crypt) in ENGLISH_FREQUENCIES.iter().zip(frequencies.iter()) {
            let relative_frequency = (crypt as f64) / (total_frequency as f64);
            total_diff += (english - relative_frequency).abs();
        }

        if total_diff < min_diff {
            min_diff = total_diff;
            best_decrypted = decrypted;
        }
    }

    return (best_decrypted, min_diff);
}
