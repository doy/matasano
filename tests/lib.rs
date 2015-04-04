extern crate matasano;
extern crate rustc_serialize as serialize;
extern crate rand;

use std::ascii::AsciiExt;
use std::borrow::ToOwned;
use std::collections::HashMap;
use std::io::prelude::*;
use std::fs::File;

use rand::{Rng, thread_rng};
use serialize::base64::FromBase64;
use serialize::hex::FromHex;

fn read_as_hex_lines (filename: &str) -> Vec<Vec<u8>> {
    let fh = File::open(filename).unwrap();
    return std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().from_hex().unwrap())
        .collect();
}

fn read_as_base64_lines (filename: &str) -> Vec<Vec<u8>> {
    let fh = File::open(filename).unwrap();
    return std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().from_base64().unwrap())
        .collect();
}

fn read_as_lines (filename: &str) -> Vec<Vec<u8>> {
    let fh = File::open(filename).unwrap();
    return std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().as_bytes().to_vec())
        .collect();
}

fn read_as_base64 (filename: &str) -> Vec<u8> {
    let fh = File::open(filename).unwrap();
    return std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>()
        .concat();
}

fn read (filename: &str) -> Vec<u8> {
    let outfh = File::open(filename).unwrap();
    return outfh.bytes().map(|c| c.unwrap()).collect();
}

fn random_aes_128_key () -> [u8; 16] {
    let mut key = [0; 16];
    thread_rng().fill_bytes(&mut key);
    return key;
}

fn coinflip () -> bool {
    thread_rng().gen()
}

#[test]
fn problem_1 () {
    let hex = "49276d206b696c6c696e6720796f757220627261\
               696e206c696b65206120706f69736f6e6f757320\
               6d757368726f6f6d".from_hex().unwrap();
    let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEg\
                  cG9pc29ub3VzIG11c2hyb29t";
    let got = matasano::to_base64(&hex[..]);
    assert_eq!(got, base64);
}

#[test]
fn problem_2 () {
    let bytes1 = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let bytes2 = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let expected = "746865206b696420646f6e277420706c6179".from_hex().unwrap();
    let got = matasano::fixed_xor(&bytes1[..], &bytes2[..]);
    assert_eq!(got, expected);
}

#[test]
fn problem_3 () {
    let ciphertext = "1b37373331363f78151b7f2b783431333d783978\
                      28372d363c78373e783a393b3736".from_hex().unwrap();
    let plaintext = b"Cooking MC's like a pound of bacon";
    let got = matasano::crack_single_byte_xor(&ciphertext[..]);
    assert_eq!(got, &plaintext[..]);
}

#[test]
fn problem_4 () {
    let possibles = read_as_hex_lines("data/4.txt");
    let plaintext = b"Now that the party is jumping\n";
    let got = matasano::find_single_byte_xor_encrypted_string(&possibles[..]);
    assert_eq!(got, plaintext);
}

#[test]
fn problem_5 () {
    let plaintext = b"Burning 'em, if you ain't quick and nimble\n\
                    I go crazy when I hear a cymbal";
    let key = b"ICE";
    let ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c63\
                      24202d623d63343c2a26226324272765272a282b\
                      2f20430a652e2c652a3124333a653e2b2027630c\
                      692b20283165286326302e27282f".from_hex().unwrap();
    let got = matasano::repeating_key_xor(plaintext, key);
    assert_eq!(got, ciphertext);
}

#[test]
fn problem_6 () {
    let ciphertext = read_as_base64("data/6.txt");
    let plaintext = read("data/6.out.txt");
    let key = matasano::crack_repeating_key_xor(&ciphertext[..]);
    let got = matasano::repeating_key_xor(&ciphertext[..], &key[..]);
    assert_eq!(got, plaintext);
}

#[test]
fn problem_7 () {
    let ciphertext = read_as_base64("data/7.txt");
    let key = b"YELLOW SUBMARINE";
    let plaintext = read("data/7.out.txt");
    let got = matasano::decrypt_aes_128_ecb(&ciphertext[..], key);
    assert_eq!(got, Some(plaintext));
}

#[test]
fn problem_8 () {
    let possibles = read_as_hex_lines("data/8.txt");
    let ciphertext = "d880619740a8a19b7840a8a31c810a3d08649af7\
                      0dc06f4fd5d2d69c744cd283e2dd052f6b641dbf\
                      9d11b0348542bb5708649af70dc06f4fd5d2d69c\
                      744cd2839475c9dfdbc1d46597949d9c7e82bf5a\
                      08649af70dc06f4fd5d2d69c744cd28397a93eab\
                      8d6aecd566489154789a6b0308649af70dc06f4f\
                      d5d2d69c744cd283d403180c98c8f6db1f2a3f9c\
                      4040deb0ab51b29933f2c123c58386b06fba186a"
                      .from_hex().unwrap();
    let got = matasano::find_aes_128_ecb_encrypted_string(&possibles[..]);
    assert_eq!(got, ciphertext);
}

#[test]
fn problem_9 () {
    let block = b"YELLOW SUBMARINE";
    let got = matasano::pad_pkcs7(block, 20);
    assert_eq!(got, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

#[test]
fn problem_10 () {
    let ciphertext = read_as_base64("data/10.txt");
    let key = b"YELLOW SUBMARINE";
    let plaintext = read("data/10.out.txt");
    let got = matasano::decrypt_aes_128_cbc(&ciphertext[..], key, &[0; 16]);
    assert_eq!(got, Some(plaintext));
}

#[test]
fn problem_11 () {
    static mut last_mode: matasano::BlockCipherMode = matasano::BlockCipherMode::ECB;

    fn random_padding (input: &[u8]) -> Vec<u8> {
        let front_padding: Vec<u8> = thread_rng()
            .gen_iter()
            .take(thread_rng().gen_range(5, 10))
            .collect();
        let back_padding: Vec<u8> = thread_rng()
            .gen_iter()
            .take(thread_rng().gen_range(5, 10))
            .collect();
        return front_padding
            .iter()
            .chain(input.iter())
            .chain(back_padding.iter())
            .map(|x| *x)
            .collect()
    }

    fn random_encrypter (input: &[u8]) -> Vec<u8> {
        let key = random_aes_128_key();
        let padded_input = random_padding(input);
        if coinflip() {
            unsafe {
                last_mode = matasano::BlockCipherMode::ECB;
            }
            return matasano::encrypt_aes_128_ecb(&padded_input[..], &key[..]);
        }
        else {
            unsafe {
                last_mode = matasano::BlockCipherMode::CBC;
            }
            let iv = random_aes_128_key();
            return matasano::encrypt_aes_128_cbc(&padded_input[..], &key[..], &iv[..]);
        }
    }

    for _ in 0..100 {
        let got = matasano::detect_ecb_cbc(&random_encrypter, 16);
        let expected = unsafe { &last_mode };
        assert_eq!(&got, expected);
    }
}

#[test]
fn problem_12 () {
    let padding = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWct\
                    dG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU\
                    aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v\
                    LCBJIGp1c3QgZHJvdmUgYnkK".from_base64().unwrap();
    let fixed_padding = |input: &[u8]| -> Vec<u8> {
        return input
            .iter()
            .chain(padding.iter())
            .map(|x| *x)
            .collect()
    };

    let key = random_aes_128_key();
    let random_encrypter = |input: &[u8]| {
        let padded_input = fixed_padding(input);
        return matasano::encrypt_aes_128_ecb(&padded_input[..], &key[..]);
    };

    let got = matasano::crack_padded_aes_128_ecb(&random_encrypter);
    assert_eq!(got, padding);
}

#[test]
fn problem_13 () {
    fn profile_for (email: &str) -> String {
        let mut params = HashMap::new();
        params.insert("email", email);
        params.insert("uid", "10");
        params.insert("role", "user");
        return matasano::create_query_string(params);
    }

    let key = random_aes_128_key();
    let encrypter = |email: &str| -> Vec<u8> {
        matasano::encrypt_aes_128_ecb(profile_for(email).as_bytes(), &key[..])
    };
    let decrypter = |ciphertext: &[u8]| -> Option<HashMap<String, String>> {
        let plaintext = matasano::decrypt_aes_128_ecb(ciphertext, &key[..]).unwrap();
        let plaintext_str = std::str::from_utf8(&plaintext[..]).unwrap();
        if let Some(params) = matasano::parse_query_string(plaintext_str) {
            return Some(
                params
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
            );
        }
        else {
            return None;
        }
    };

    let (email, ciphertexts) = matasano::crack_querystring_aes_128_ecb(&encrypter);
    let mut expected = HashMap::new();
    expected.insert("email".to_owned(), email);
    expected.insert("uid".to_owned(), "10".to_owned());
    expected.insert("role".to_owned(), "admin".to_owned());
    assert!(ciphertexts.iter().any(|ciphertext| {
        decrypter(ciphertext).map(|params| params == expected).unwrap_or(false)
    }));
}

#[test]
fn problem_14 () {
    let padding = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWct\
                    dG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU\
                    aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v\
                    LCBJIGp1c3QgZHJvdmUgYnkK".from_base64().unwrap();
    let front_padding: Vec<u8> = thread_rng()
        .gen_iter()
        .take(thread_rng().gen_range(1, 100))
        .collect();
    let fixed_padding = |input: &[u8]| -> Vec<u8> {
        return front_padding
            .iter()
            .chain(input.iter())
            .chain(padding.iter())
            .map(|x| *x)
            .collect()
    };

    let key = random_aes_128_key();
    let random_encrypter = |input: &[u8]| {
        let padded_input = fixed_padding(input);
        return matasano::encrypt_aes_128_ecb(&padded_input[..], &key[..]);
    };

    let got = matasano::crack_padded_aes_128_ecb_with_prefix(&random_encrypter);
    assert_eq!(got, padding);
}

#[test]
fn problem_15 () {
    assert_eq!(
        matasano::unpad_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04"),
        Some(&b"ICE ICE BABY"[..])
    );
    assert_eq!(
        matasano::unpad_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05"),
        None
    );
    assert_eq!(
        matasano::unpad_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04"),
        None
    );
    assert_eq!(
        matasano::unpad_pkcs7(b"ICE ICE BABY\x00"),
        None
    );
    assert_eq!(
        matasano::unpad_pkcs7(b"\x04\x04\x04\x04"),
        Some(&b""[..])
    );
}

#[test]
fn problem_16 () {
    let key = random_aes_128_key();
    let iv = random_aes_128_key();
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let admin = ";admin=true;";

    let escape = |input: &str| {
        input.replace("%", "%25").replace(";", "%3B").replace("=", "%3D")
    };

    let encode = |input: &str| -> Vec<u8> {
        let plaintext: Vec<u8> = prefix
            .as_bytes()
            .iter()
            .chain(escape(input).as_bytes().iter())
            .chain(suffix.as_bytes().iter())
            .map(|x| *x)
            .collect();
        return matasano::encrypt_aes_128_cbc(&plaintext[..], &key[..], &iv[..]);
    };

    let verify = |ciphertext: &[u8]| -> bool {
        let plaintext = matasano::decrypt_aes_128_cbc(ciphertext, &key[..], &iv[..]).unwrap();
        return (0..(plaintext.len() - admin.len())).any(|i| {
            plaintext
                .iter()
                .skip(i)
                .zip(admin.as_bytes().iter())
                .all(|(&c1, &c2)| c1 == c2)
        });
    };

    let ciphertext = matasano::crack_cbc_bitflipping(&encode);
    assert!(verify(&ciphertext[..]));
}

#[test]
fn problem_17 () {
    let strings = [
        &b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="[..],
        &b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="[..],
        &b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="[..],
        &b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="[..],
        &b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"[..],
        &b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="[..],
        &b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="[..],
        &b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="[..],
        &b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="[..],
        &b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"[..],
    ];
    let key = random_aes_128_key();

    static mut chosen_plaintext_idx: usize = 0;
    let encrypter = || {
        let idx = thread_rng().gen_range(0, strings.len());
        let plaintext = strings[idx].from_base64().unwrap();
        unsafe { chosen_plaintext_idx = idx };
        let iv = random_aes_128_key();
        return (
            iv,
            matasano::encrypt_aes_128_cbc(&plaintext[..], &key[..], &iv[..])
        );
    };

    let validator = |iv: &[u8], ciphertext: &[u8]| {
        let plaintext = matasano::decrypt_aes_128_cbc(
            ciphertext,
            &key[..],
            &iv[..]
        );
        return plaintext.is_some();
    };

    let (iv, ciphertext) = encrypter();
    for _ in 0..5 {
        let plaintext = matasano::crack_cbc_padding_oracle(
            &iv[..],
            &ciphertext[..],
            &validator
        );
        let idx = unsafe { chosen_plaintext_idx.clone() };
        let expected = strings[idx].from_base64().unwrap();
        assert_eq!(plaintext, expected);
    }
}

#[test]
fn problem_18 () {
    let ciphertext = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syL\
                       XzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".from_base64().unwrap();
    let plaintext = &b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "[..];
    let got = matasano::aes_128_ctr(
        &ciphertext[..],
        b"YELLOW SUBMARINE",
        0
    );
    assert_eq!(got, plaintext);
}

// #[test]
// fn problem_19 () {
//     let key = random_aes_128_key();
//     let ciphertexts = read_as_base64_lines("data/19.txt")
//         .iter()
//         .map(|line| matasano::aes_128_ctr(&line[..], &key[..], 0))
//         .collect();
//     let plaintexts = matasano::crack_fixed_nonce_ctr_substitutions();
// }

#[test]
fn problem_20 () {
    fn normalize (line_list: Vec<Vec<u8>>, len: usize) -> Vec<Vec<u8>> {
        line_list
            .iter()
            .map(|line| line.to_ascii_lowercase())
            .map(|line| line.iter().take(len).map(|x| *x).collect())
            .collect()
    }

    let key = random_aes_128_key();
    let ciphertexts = read_as_base64_lines("data/20.txt")
        .iter()
        .map(|line| matasano::aes_128_ctr(&line[..], &key[..], 0))
        .collect();
    let expected = read_as_lines("data/20.out.txt");

    let plaintexts = matasano::crack_fixed_nonce_ctr_statistically(
        ciphertexts
    );

    assert_eq!(
        normalize(plaintexts, 27),
        normalize(expected, 27)
    );
}
