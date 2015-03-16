use openssl;
use std::collections::HashSet;

use primitives::{fixed_xor, pad_pkcs7, unpad_pkcs7};

pub fn decrypt_aes_128_ecb (bytes: &[u8], key: &[u8]) -> Vec<u8> {
    return openssl::crypto::symm::decrypt(
        openssl::crypto::symm::Type::AES_128_ECB,
        key,
        vec![],
        bytes
    )
}

pub fn decrypt_aes_128_cbc (bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv.clone();
    let mut plaintext = vec![];
    for block in bytes.chunks(16) {
        let plaintext_block = fixed_xor(
            &decrypt_aes_128_ecb(&pad_pkcs7(block, 16)[..], key)[..],
            prev
        );
        for c in plaintext_block {
            plaintext.push(c);
        }
        prev = block.clone();
    }
    return unpad_pkcs7(&plaintext[..]).to_vec();
}

pub fn find_aes_128_ecb_encrypted_string (inputs: &[Vec<u8>]) -> Vec<u8> {
    let mut max_dups = 0;
    let mut found = vec![];
    for input in inputs {
        let mut set = HashSet::new();
        let mut dups = 0;
        for block in input.chunks(16) {
            if !set.insert(block) {
                dups += 1;
            }
        }
        if dups > max_dups {
            max_dups = dups;
            found = input.clone();
        }
    }
    return found;
}
