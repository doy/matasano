use data::ENGLISH_FREQUENCIES;
use primitives::{fixed_xor, hamming, repeating_key_xor};

use std;
use std::ascii::AsciiExt;
use std::num::Float;

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

pub fn crack_single_byte_xor (input: &[u8]) -> Vec<u8> {
    let (key, _) = crack_single_byte_xor_with_confidence(input);
    return repeating_key_xor(input, &[key]);
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
        if decrypted.iter().any(|&c| c != b'\n' && (c < 0x20 || c > 0x7E)) {
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
