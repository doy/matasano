#![allow(dead_code)]

use rand::{Rng, RngCore};
use std::fs::File;
use std::io::prelude::*;

use rustc_serialize::base64::FromBase64;
use rustc_serialize::hex::FromHex;

pub fn read_as_hex_lines(filename: &str) -> Vec<Vec<u8>> {
    let fh = File::open(filename).unwrap();
    return std::io::BufReader::new(fh)
        .lines()
        .map(|line| line.unwrap().from_hex().unwrap())
        .collect();
}

pub fn read_as_base64_lines(filename: &str) -> Vec<Vec<u8>> {
    let fh = File::open(filename).unwrap();
    return std::io::BufReader::new(fh)
        .lines()
        .map(|line| line.unwrap().from_base64().unwrap())
        .collect();
}

pub fn read_as_lines(filename: &str) -> Vec<Vec<u8>> {
    let fh = File::open(filename).unwrap();
    return std::io::BufReader::new(fh)
        .lines()
        .map(|line| line.unwrap().as_bytes().to_vec())
        .collect();
}

pub fn read_as_base64(filename: &str) -> Vec<u8> {
    let fh = File::open(filename).unwrap();
    return std::io::BufReader::new(fh)
        .lines()
        .map(|line| line.unwrap().from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>()
        .concat();
}

pub fn read(filename: &str) -> Vec<u8> {
    let outfh = File::open(filename).unwrap();
    return outfh.bytes().map(|c| c.unwrap()).collect();
}

pub fn write(filename: &str, data: &[u8]) {
    let mut outfh = File::create(filename).unwrap();
    outfh.write(data).unwrap();
}

pub fn random_aes_128_key() -> [u8; 16] {
    let mut key = [0; 16];
    rand::thread_rng().fill_bytes(&mut key);
    return key;
}

pub fn coinflip() -> bool {
    rand::thread_rng().gen()
}

pub fn now() -> u32 {
    return time::now().to_timespec().sec as u32;
}
