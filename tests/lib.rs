extern crate matasano;
extern crate "rustc-serialize" as serialize;

use std::io::prelude::*;
use std::fs::File;

use serialize::base64::FromBase64;
use serialize::hex::FromHex;

#[test]
fn problem_1 () {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(matasano::to_base64(&hex.from_hex().unwrap()[..]), base64);
}

#[test]
fn problem_2 () {
    let bytes1 = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let bytes2 = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let expected = "746865206b696420646f6e277420706c6179".from_hex().unwrap();
    assert_eq!(matasano::fixed_xor(&bytes1[..], &bytes2[..]), expected);
}

#[test]
fn problem_3 () {
    let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex().unwrap();
    let plaintext = b"Cooking MC's like a pound of bacon";
    assert_eq!(matasano::crack_single_byte_xor(&encrypted[..]), plaintext);
}

#[test]
fn problem_4 () {
    let fh = File::open("data/4.txt").unwrap();
    let possibles = std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().from_hex().unwrap())
        .collect::<Vec<Vec<u8>>>();
    assert_eq!(matasano::find_single_byte_xor_encrypted_string(&possibles[..]), b"nOW\0THAT\0THE\0PARTY\0IS\0JUMPING*");
}

#[test]
fn problem_5 () {
    let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";
    let ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".from_hex().unwrap();
    assert_eq!(matasano::repeating_key_xor(plaintext, key), ciphertext);
}

#[test]
fn problem_6 () {
    let fh = File::open("data/6.txt").unwrap();
    let ciphertext = std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>()
        .concat();
    let outfh = File::open("data/6.out.txt").unwrap();
    let plaintext = outfh.bytes().map(|c| c.unwrap()).collect();
    let got = matasano::crack_repeating_key_xor(&ciphertext[..]);
    assert_eq!(got, plaintext);
}

#[test]
fn problem_7 () {
    let fh = File::open("data/7.txt").unwrap();
    let ciphertext = std::io::BufStream::new(fh)
        .lines()
        .map(|line| line.unwrap().from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>()
        .concat();
    let key = b"YELLOW SUBMARINE";
    let got = matasano::decrypt_aes_128_ecb(&ciphertext[..], key);
    let outfh = File::open("data/7.out.txt").unwrap();
    let plaintext = outfh.bytes().map(|c| c.unwrap()).collect();
    assert_eq!(got, plaintext);
}
