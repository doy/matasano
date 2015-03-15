extern crate "rustc-serialize" as serialize;

use std::ascii::AsciiExt;
use std::num::Float;

use serialize::base64::{ToBase64,STANDARD};

const ENGLISH_FREQUENCIES: [f64; 26] = [
    0.0804,
    0.0148,
    0.0334,
    0.0382,
    0.1249,
    0.0240,
    0.0187,
    0.0505,
    0.0757,
    0.0016,
    0.0054,
    0.0407,
    0.0251,
    0.0723,
    0.0764,
    0.0214,
    0.0012,
    0.0628,
    0.0651,
    0.0928,
    0.0273,
    0.0105,
    0.0168,
    0.0023,
    0.0166,
    0.0009,
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

pub fn repeating_key_xor (plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    return fixed_xor(
        plaintext,
        &key
            .iter()
            .cycle()
            .take(plaintext.len())
            .map(|c| *c)
            .collect::<Vec<u8>>()[..]
    );
}

pub fn crack_single_byte_xor (input: &[u8]) -> Vec<u8> {
    let (key, _) = crack_single_byte_xor_with_confidence(input);
    return repeating_key_xor(input, &[key]);
}

pub fn find_single_byte_xor_encrypted_string (inputs: &[Vec<u8>]) -> Vec<u8> {
    let mut min_diff = 100.0;
    let mut best_decrypted = vec![];
    for input in inputs {
        let (key, diff) = crack_single_byte_xor_with_confidence(input);
        if diff < min_diff {
            min_diff = diff;
            best_decrypted = repeating_key_xor(input, &[key]);
        }
    }
    return best_decrypted;
}

pub fn crack_repeating_key_xor (input: &[u8]) -> Vec<u8> {
    let mut keysizes = vec![];
    for keysize in 2..40 {
        let distance1 = hamming(
            &input[(keysize * 0)..(keysize * 1)],
            &input[(keysize * 1)..(keysize * 2)]
        ) as f64;
        let distance2 = hamming(
            &input[(keysize * 1)..(keysize * 2)],
            &input[(keysize * 2)..(keysize * 3)]
        ) as f64;
        let distance3 = hamming(
            &input[(keysize * 2)..(keysize * 3)],
            &input[(keysize * 3)..(keysize * 4)]
        ) as f64;
        let distance = distance1 + distance2 + distance3 / 3.0;
        let normal_distance = distance / (keysize as f64);
        keysizes.push((keysize, normal_distance));
        if keysizes.len() > 5 {
            let (idx, _) = keysizes
                .iter()
                .enumerate()
                .fold(
                    (0, (0, 0.0)),
                    |(accidx, (accsize, accdist)), (idx, &(size, dist))| {
                        if dist > accdist {
                            (idx, (size, dist))
                        }
                        else {
                            (accidx, (accsize, accdist))
                        }
                    }
                );
            keysizes.swap_remove(idx);
        }
    }

    let mut min_diff = 100.0;
    let mut best_key = vec![];
    for (keysize, _) in keysizes {
        let strides: Vec<Vec<u8>> = (0..keysize)
            .map(|n| {
                // XXX sigh ):
                let mut elts = vec![];
                for (i, &c) in input.iter().enumerate() {
                    if i % keysize == n {
                        elts.push(c);
                    }
                }
                elts
            })
            .collect();
        let cracked: Vec<(u8, f64)> = strides
            .iter()
            .map(|input| crack_single_byte_xor_with_confidence(input))
            .collect();
        let diff = cracked
            .iter()
            .map(|&(_, diff)| diff)
            .fold(0.0, |acc, x| acc + x);
        let key = cracked
            .iter()
            .map(|&(c, _)| c)
            .collect();
        let normal_diff = diff / (keysize as f64);
        if normal_diff < min_diff {
            min_diff = normal_diff;
            best_key = key;
        }
    }

    return repeating_key_xor(input, &best_key[..]);
}

fn hamming (bytes1: &[u8], bytes2: &[u8]) -> u64 {
    count_bits(&fixed_xor(bytes1, bytes2)[..])
}

fn count_bits (bytes: &[u8]) -> u64 {
    bytes.iter().map(|&c| { count_bits_byte(c) }).fold(0, |acc, n| acc + n)
}

fn count_bits_byte (byte: u8) -> u64 {
    (((byte & (0x01 << 0)) >> 0)
    + ((byte & (0x01 << 1)) >> 1)
    + ((byte & (0x01 << 2)) >> 2)
    + ((byte & (0x01 << 3)) >> 3)
    + ((byte & (0x01 << 4)) >> 4)
    + ((byte & (0x01 << 5)) >> 5)
    + ((byte & (0x01 << 6)) >> 6)
    + ((byte & (0x01 << 7)) >> 7)) as u64
}

fn crack_single_byte_xor_with_confidence (input: &[u8]) -> (u8, f64) {
    let mut min_diff = 100.0;
    let mut best_key = 0;
    for a in 0..256u16 {
        let decrypted = fixed_xor(
            input,
            &std::iter::repeat(a as u8)
                .take(input.len())
                .collect::<Vec<u8>>()[..]
        );
        if !decrypted.is_ascii() {
            continue;
        }
        let lowercase = decrypted.to_ascii_lowercase();
        let mut frequencies = [0; 26];
        let mut total_frequency = 0;
        let mut extra_frequencies = 0;
        for c in lowercase {
            total_frequency += 1;
            if c >= 0x61 && c <= 0x7A {
                frequencies[(c - 0x61) as usize] += 1;
            }
            else {
                extra_frequencies += 1;
            }
        }

        let mut total_diff = 0.0;
        for (&english, &crypt) in ENGLISH_FREQUENCIES.iter().zip(frequencies.iter()) {
            let relative_frequency = (crypt as f64) / (total_frequency as f64);
            total_diff += (english - relative_frequency).abs();
        }
        total_diff += (extra_frequencies as f64) / (total_frequency as f64);

        if total_diff < min_diff {
            min_diff = total_diff;
            best_key = a as u8;
        }
    }

    return (best_key, min_diff);
}

#[test]
fn test_hamming () {
    assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
}
