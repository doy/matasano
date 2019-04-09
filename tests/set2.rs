extern crate matasano;
extern crate rand;
extern crate rustc_serialize as serialize;

use std::borrow::ToOwned;
use std::collections::HashMap;

use rand::Rng;
use serialize::base64::FromBase64;

mod util;

#[test]
fn problem_9() {
    let block = b"YELLOW SUBMARINE";
    let got = matasano::pad_pkcs7(block, 20);
    assert_eq!(got, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

#[test]
fn problem_10() {
    let ciphertext = util::read_as_base64("data/10.txt");
    let key = b"YELLOW SUBMARINE";
    let plaintext = util::read("data/10.out.txt");
    let got = matasano::decrypt_aes_128_cbc(&ciphertext[..], key, &[0; 16]);
    assert_eq!(got, Some(plaintext));
}

#[test]
fn problem_11() {
    static mut LAST_MODE: matasano::BlockCipherMode =
        matasano::BlockCipherMode::ECB;

    fn random_padding(input: &[u8]) -> Vec<u8> {
        let front_padding: Vec<u8> = rand::thread_rng()
            .sample_iter(&rand::distributions::Standard)
            .take(rand::thread_rng().gen_range(5, 10))
            .collect();
        let back_padding: Vec<u8> = rand::thread_rng()
            .sample_iter(&rand::distributions::Standard)
            .take(rand::thread_rng().gen_range(5, 10))
            .collect();
        return front_padding
            .iter()
            .chain(input.iter())
            .chain(back_padding.iter())
            .map(|x| *x)
            .collect();
    }

    fn random_encrypter(input: &[u8]) -> Vec<u8> {
        let key = util::random_aes_128_key();
        let padded_input = random_padding(input);
        if util::coinflip() {
            unsafe {
                LAST_MODE = matasano::BlockCipherMode::ECB;
            }
            return matasano::encrypt_aes_128_ecb(&padded_input[..], &key[..]);
        } else {
            unsafe {
                LAST_MODE = matasano::BlockCipherMode::CBC;
            }
            let iv = util::random_aes_128_key();
            return matasano::encrypt_aes_128_cbc(
                &padded_input[..],
                &key[..],
                &iv[..],
            );
        }
    }

    for _ in 0..100 {
        let got = matasano::detect_ecb_cbc(&random_encrypter, 16);
        let expected = unsafe { &LAST_MODE };
        assert_eq!(&got, expected);
    }
}

#[test]
fn problem_12() {
    let padding = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWct\
                    dG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU\
                    aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v\
                    LCBJIGp1c3QgZHJvdmUgYnkK"
        .from_base64()
        .unwrap();
    let fixed_padding = |input: &[u8]| -> Vec<u8> {
        return input.iter().chain(padding.iter()).map(|x| *x).collect();
    };

    let key = util::random_aes_128_key();
    let random_encrypter = |input: &[u8]| {
        let padded_input = fixed_padding(input);
        return matasano::encrypt_aes_128_ecb(&padded_input[..], &key[..]);
    };

    let got = matasano::crack_padded_aes_128_ecb(&random_encrypter);
    assert_eq!(got, padding);
}

#[test]
fn problem_13() {
    fn profile_for(email: &str) -> String {
        let mut params = HashMap::new();
        params.insert("email", email);
        params.insert("uid", "10");
        params.insert("role", "user");
        return matasano::create_query_string(params);
    }

    let key = util::random_aes_128_key();
    let encrypter = |email: &str| -> Vec<u8> {
        matasano::encrypt_aes_128_ecb(profile_for(email).as_bytes(), &key[..])
    };
    let decrypter = |ciphertext: &[u8]| -> Option<HashMap<String, String>> {
        let plaintext = matasano::decrypt_aes_128_ecb(ciphertext, &key[..]);
        let plaintext_str = std::str::from_utf8(&plaintext[..]).unwrap();
        if let Some(params) = matasano::parse_query_string(plaintext_str) {
            return Some(
                params
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            );
        } else {
            return None;
        }
    };

    let (email, ciphertexts) =
        matasano::crack_querystring_aes_128_ecb(&encrypter);
    let mut expected = HashMap::new();
    expected.insert("email".to_owned(), email);
    expected.insert("uid".to_owned(), "10".to_owned());
    expected.insert("role".to_owned(), "admin".to_owned());
    assert!(ciphertexts.iter().any(|ciphertext| decrypter(ciphertext)
        .map(|params| params == expected)
        .unwrap_or(false)));
}

#[test]
fn problem_14() {
    let padding = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWct\
                    dG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU\
                    aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v\
                    LCBJIGp1c3QgZHJvdmUgYnkK"
        .from_base64()
        .unwrap();
    let front_padding: Vec<u8> = rand::thread_rng()
        .sample_iter(&rand::distributions::Standard)
        .take(rand::thread_rng().gen_range(1, 100))
        .collect();
    let fixed_padding = |input: &[u8]| -> Vec<u8> {
        return front_padding
            .iter()
            .chain(input.iter())
            .chain(padding.iter())
            .map(|x| *x)
            .collect();
    };

    let key = util::random_aes_128_key();
    let random_encrypter = |input: &[u8]| {
        let padded_input = fixed_padding(input);
        return matasano::encrypt_aes_128_ecb(&padded_input[..], &key[..]);
    };

    let got =
        matasano::crack_padded_aes_128_ecb_with_prefix(&random_encrypter);
    assert_eq!(got, padding);
}

#[test]
fn problem_15() {
    assert_eq!(
        matasano::unpad_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04"),
        Some(&b"ICE ICE BABY"[..])
    );
    assert_eq!(matasano::unpad_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05"), None);
    assert_eq!(matasano::unpad_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04"), None);
    assert_eq!(matasano::unpad_pkcs7(b"ICE ICE BABY\x00"), None);
    assert_eq!(matasano::unpad_pkcs7(b"\x04\x04\x04\x04"), Some(&b""[..]));
}

#[test]
fn problem_16() {
    let key = util::random_aes_128_key();
    let iv = util::random_aes_128_key();
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let admin = ";admin=true;";

    let escape = |input: &str| {
        input
            .replace("%", "%25")
            .replace(";", "%3B")
            .replace("=", "%3D")
    };

    let encode = |input: &str| -> Vec<u8> {
        let plaintext: Vec<u8> = prefix
            .as_bytes()
            .iter()
            .chain(escape(input).as_bytes().iter())
            .chain(suffix.as_bytes().iter())
            .map(|x| *x)
            .collect();
        return matasano::encrypt_aes_128_cbc(
            &plaintext[..],
            &key[..],
            &iv[..],
        );
    };

    let verify = |ciphertext: &[u8]| -> bool {
        let plaintext =
            matasano::decrypt_aes_128_cbc(ciphertext, &key[..], &iv[..])
                .unwrap();
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
