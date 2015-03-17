extern crate matasano;
extern crate "rustc-serialize" as serialize;
extern crate rand;

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
    assert_eq!(got, plaintext);
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
    let got = matasano::crack_repeating_key_xor(&ciphertext[..]);
    assert_eq!(got, plaintext);
}

#[test]
fn problem_7 () {
    let ciphertext = read_as_base64("data/7.txt");
    let key = b"YELLOW SUBMARINE";
    let plaintext = read("data/7.out.txt");
    let got = matasano::decrypt_aes_128_ecb(&ciphertext[..], key);
    assert_eq!(got, plaintext);
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
    assert_eq!(got, plaintext);
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
