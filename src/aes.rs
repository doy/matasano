use std;
use std::collections::HashSet;

use openssl;

use primitives::{fixed_xor, pad_pkcs7, unpad_pkcs7};

#[derive(PartialEq,Eq,Debug)]
pub enum BlockCipherMode {
    ECB,
    CBC,
}

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

pub fn encrypt_aes_128_ecb (bytes: &[u8], key: &[u8]) -> Vec<u8> {
    return openssl::crypto::symm::encrypt(
        openssl::crypto::symm::Type::AES_128_ECB,
        key,
        vec![],
        bytes
    )
}

pub fn encrypt_aes_128_cbc (bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv.to_vec();
    let mut ciphertext = vec![];
    for block in bytes.chunks(16) {
        let plaintext_block = fixed_xor(&pad_pkcs7(block, 16)[..], &prev[..]);
        let mut ciphertext_block = encrypt_aes_128_ecb(&plaintext_block[..], key);
        ciphertext_block.truncate(16);
        for &c in ciphertext_block.iter() {
            ciphertext.push(c);
        }
        prev = ciphertext_block.clone();
    }
    return ciphertext;
}

pub fn find_aes_128_ecb_encrypted_string (inputs: &[Vec<u8>]) -> Vec<u8> {
    let mut max_dups = 0;
    let mut found = vec![];
    for input in inputs {
        let dups = count_duplicate_blocks(input, 16);
        if dups > max_dups {
            max_dups = dups;
            found = input.clone();
        }
    }
    return found;
}

pub fn detect_ecb_cbc<F> (f: F, block_size: usize) -> BlockCipherMode where F: Fn(&[u8]) -> Vec<u8> {
    if block_size >= std::u8::MAX as usize {
        panic!("invalid block size: {}", block_size);
    }
    let block_size_byte = block_size as u8;
    let plaintext: Vec<u8> = (0..block_size_byte)
        .cycle()
        .take(block_size * 2)
        .flat_map(|n| std::iter::repeat(n).take(block_size + 1))
        .collect();
    let ciphertext = f(&plaintext[..]);

    if count_duplicate_blocks(&ciphertext[..], block_size) >= block_size {
        return BlockCipherMode::ECB;
    }
    else {
        return BlockCipherMode::CBC;
    }
}

fn count_duplicate_blocks (input: &[u8], block_size: usize) -> usize {
    let mut set = HashSet::new();
    let mut dups = 0;
    for block in input.chunks(block_size) {
        if !set.insert(block) {
            dups += 1;
        }
    }
    return dups;
}

#[test]
fn test_encrypt_decrypt () {
    let plaintext = b"Summertime and the wind is blowing outside in lower \
                     Chelsea and I don't know what I'm doing in the city, the \
                     sun is always in my eyes";
    let key = b"YELLOW SUBMARINE";
    let iv = [0; 16];

    let ciphertext_ecb = encrypt_aes_128_ecb(&plaintext[..], &key[..]);
    let ciphertext_cbc = encrypt_aes_128_cbc(&plaintext[..], &key[..], &iv[..]);

    let plaintext2_ecb = decrypt_aes_128_ecb(&ciphertext_ecb[..], &key[..]);
    let plaintext2_cbc = decrypt_aes_128_cbc(&ciphertext_cbc[..], &key[..], &iv[..]);

    let ciphertext2_ecb = encrypt_aes_128_ecb(&plaintext2_ecb[..], &key[..]);
    let ciphertext2_cbc = encrypt_aes_128_cbc(&plaintext2_cbc[..], &key[..], &iv[..]);

    assert_eq!(plaintext, plaintext2_ecb);
    assert_eq!(plaintext, plaintext2_cbc);
    assert_eq!(ciphertext_ecb, ciphertext2_ecb);
    assert_eq!(ciphertext_cbc, ciphertext2_cbc);
}
