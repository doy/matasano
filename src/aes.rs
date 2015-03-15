use openssl;
use std::collections::HashSet;

use primitives::fixed_xor;

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
        // XXX not sure what's going on here - decrypt_aes_128_ecb doesn't
        // decrypt the last block?
        let double_block: Vec<u8> = block
            .iter()
            .chain(block.iter()).map(|x| *x)
            .collect();
        let plaintext_block = fixed_xor(
            &decrypt_aes_128_ecb(&double_block[..], key)[..],
            prev
        );
        for &c in &plaintext_block[..16] {
            plaintext.push(c);
        }
        prev = block.clone();
    }
    let padding = plaintext[plaintext.len() - 1];
    let new_len = plaintext.len() - padding as usize;
    plaintext.truncate(new_len);
    return plaintext;
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
