use std;
use std::borrow::ToOwned;
use std::collections::{HashMap, HashSet};

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

pub fn detect_ecb_cbc<F> (f: &F, block_size: usize) -> BlockCipherMode where F: Fn(&[u8]) -> Vec<u8> {
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

pub fn crack_padded_aes_128_ecb<F> (f: &F) -> Vec<u8> where F: Fn(&[u8]) -> Vec<u8> {
    let block_size = find_block_size(f);
    if detect_ecb_cbc(f, block_size) != BlockCipherMode::ECB {
        panic!("Can only crack ECB-encrypted data");
    }

    let mut plaintext = vec![];

    let get_block = |input: &[u8], i| {
        let encrypted = f(input);
        let block_number = i / block_size;
        let low = block_number * block_size;
        let high = (block_number + 1) * block_size;
        encrypted[low..high].to_vec()
    };

    let mut i = 0;
    loop {
        let mut map = HashMap::new();

        let prefix: Vec<u8> = std::iter::repeat(b'A')
            .take(block_size - ((i % block_size) + 1))
            .collect();
        for c in 0..256 {
            let mut prefix_with_next_char = prefix.clone();
            for &c in plaintext.iter() {
                prefix_with_next_char.push(c);
            }
            prefix_with_next_char.push(c as u8);
            map.insert(get_block(&prefix_with_next_char[..], i), c as u8);
        }

        let next_char = map.get(&get_block(&prefix[..], i));
        if next_char.is_some() {
            plaintext.push(*next_char.unwrap());
        }
        else {
            break;
        }

        i += 1;
    }

    return unpad_pkcs7(&plaintext[..]).to_vec();
}

pub fn crack_padded_aes_128_ecb_with_prefix<F> (f: &F) -> Vec<u8> where F: Fn(&[u8]) -> Vec<u8> {
    let (block_size, prefix_len) = find_block_size_and_fixed_prefix_len(f);
    let wrapped_f = |input: &[u8]| {
        let alignment_padding = block_size - (prefix_len % block_size);
        let padded_input: Vec<u8> = std::iter::repeat(b'A')
            .take(alignment_padding)
            .chain(input.iter().map(|x| *x))
            .collect();
        return f(&padded_input[..])
            .iter()
            .skip(prefix_len + alignment_padding)
            .map(|x| *x)
            .collect();
    };
    return crack_padded_aes_128_ecb(&wrapped_f);
}

pub fn crack_querystring_aes_128_ecb<F> (encrypter: F) -> (String, Vec<Vec<u8>>) where F: Fn(&str) -> Vec<u8> {
    fn incr_map_element (map: &mut HashMap<Vec<u8>, usize>, key: Vec<u8>) {
        if let Some(val) = map.get_mut(&key) {
            *val += 1;
            return;
        }
        map.insert(key, 1);
    };

    // find blocks that correspond to "uid=10&role=user" or "role=user&uid=10"
    let find_uid_role_blocks = || {
        let mut map = HashMap::new();
        for c in 32..127 {
            let email_bytes: Vec<u8> = std::iter::repeat(c).take(9).collect();
            let email = std::str::from_utf8(&email_bytes[..]).unwrap();
            let ciphertext = encrypter(email);
            incr_map_element(&mut map, ciphertext[..16].to_vec());
            incr_map_element(&mut map, ciphertext[16..32].to_vec());
        }

        let mut most_common_blocks = vec![];
        for (k, v) in map {
            most_common_blocks.push((k, v));
            if most_common_blocks.len() > 2 {
                let (idx, _) = most_common_blocks
                    .iter()
                    .enumerate()
                    .fold(
                        (0, (vec![], 10000)),
                        |(aidx, (ablock, acount)), (idx, &(ref block, count))| {
                            if count < acount {
                                (idx, (block.clone(), count))
                            }
                            else {
                                (aidx, (ablock.clone(), acount))
                            }
                        }
                    );
                most_common_blocks.swap_remove(idx);
            }
        }

        if let [(ref block1, _), (ref block2, _)] = &most_common_blocks[..] {
            return (block1.clone(), block2.clone());
        }
        else {
            panic!("couldn't find most common blocks");
        }
    };

    // encrypt:
    // email=..........admin<pcks7 padding>...............&uid=10&role=user
    let calculate_admin_block = |block1, block2| {
        for _ in 0..1000 {
            let email = "blorg@bar.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b...............";
            let ciphertext = encrypter(email);
            if &ciphertext[48..64] == block1 || &ciphertext[48..64] == block2 {
                return ciphertext[16..32].to_vec();
            }
        }
        panic!("couldn't find a ciphertext with the correct role/uid block");
    };

    // find all possible encryptions with email=............ and then replace
    // the last block with the padded admin block above
    let calculate_possible_admin_ciphertexts = |admin_block: Vec<u8>| {
        let email = "blorg@bar.com";
        let mut possibles = vec![];
        while possibles.len() < 6 {
            let ciphertext = encrypter(email);
            let modified_ciphertext = ciphertext
                .iter()
                .take(32)
                .chain(admin_block.iter())
                .map(|x| *x)
                .collect();
            if !possibles.iter().any(|possible| possible == &modified_ciphertext) {
                possibles.push(modified_ciphertext);
            }
        }
        return (email.to_owned(), possibles);
    };

    let (block1, block2) = find_uid_role_blocks();
    let admin_block = calculate_admin_block(block1, block2);
    return calculate_possible_admin_ciphertexts(admin_block);
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

fn find_block_size<F> (f: &F) -> usize where F: Fn(&[u8]) -> Vec<u8> {
    let (block_size, _) = find_block_size_and_fixed_prefix_len(f);
    return block_size;
}

fn find_block_size_and_fixed_prefix_len<F> (f: &F) -> (usize, usize) where F: Fn(&[u8]) -> Vec<u8> {
    let fixed_prefix_len = find_fixed_block_prefix_len(f);
    let byte = b'A';
    let mut prev = f(&[b'f']);
    let mut len = 0;
    loop {
        let prefix: Vec<u8> = std::iter::repeat(byte)
            .take(len)
            .collect();
        let next = f(&prefix[..]);

        let prefix_len = shared_prefix_len(
            prev.iter(),
            next.iter()
        );
        if prefix_len > fixed_prefix_len {
            let block_size = prefix_len - fixed_prefix_len;
            return (block_size, fixed_prefix_len + block_size - (len - 1));
        }

        prev = next;
        len += 1;
    }
}

fn find_fixed_block_prefix_len<F> (f: &F) -> usize where F: Fn(&[u8]) -> Vec<u8> {
    let ciphertext1 = f(b"");
    let ciphertext2 = f(b"A");
    return shared_prefix_len(ciphertext1.iter(), ciphertext2.iter());
}

fn shared_prefix_len<I> (i1: I, i2: I) -> usize where I: Iterator, <I as Iterator>::Item: PartialEq {
    return i1
        .zip(i2)
        .take_while(|&(ref c1, ref c2)| { c1 == c2 })
        .count();
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

    assert_eq!(&plaintext[..], plaintext2_ecb);
    assert_eq!(&plaintext[..], plaintext2_cbc);
    assert_eq!(ciphertext_ecb, ciphertext2_ecb);
    assert_eq!(ciphertext_cbc, ciphertext2_cbc);
}
