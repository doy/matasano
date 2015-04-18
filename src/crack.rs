use std::ascii::AsciiExt;
use std::borrow::ToOwned;
use std::collections::{HashMap, HashSet};
use rand::{Rng, SeedableRng};

use aes::encrypt_aes_128_cbc;
use data::ENGLISH_FREQUENCIES;
use primitives::{fixed_xor, unpad_pkcs7, hamming, repeating_key_xor};
use random::MersenneTwister;

#[derive(PartialEq,Eq,Debug)]
pub enum BlockCipherMode {
    ECB,
    CBC,
}

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
        let (key, diff) = crack_repeating_key_xor_with_keysize(input, keysize);
        if diff < min_diff {
            min_diff = diff;
            best_key = key;
        }
    }

    return best_key;
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
    if block_size >= ::std::u8::MAX as usize {
        panic!("invalid block size: {}", block_size);
    }
    let block_size_byte = block_size as u8;
    let plaintext: Vec<u8> = (0..block_size_byte)
        .cycle()
        .take(block_size * 2)
        .flat_map(|n| ::std::iter::repeat(n).take(block_size + 1))
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

        let prefix: Vec<u8> = ::std::iter::repeat(b'A')
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

    return unpad_pkcs7(&plaintext[..]).expect("invalid padding").to_vec();
}

pub fn crack_padded_aes_128_ecb_with_prefix<F> (f: &F) -> Vec<u8> where F: Fn(&[u8]) -> Vec<u8> {
    let (block_size, prefix_len) = find_block_size_and_fixed_prefix_len(f);
    let wrapped_f = |input: &[u8]| {
        let alignment_padding = block_size - (prefix_len % block_size);
        let padded_input: Vec<u8> = ::std::iter::repeat(b'A')
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

pub fn crack_querystring_aes_128_ecb<F> (encrypter: &F) -> (String, Vec<Vec<u8>>) where F: Fn(&str) -> Vec<u8> {
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
            let email_bytes: Vec<u8> = ::std::iter::repeat(c).take(9).collect();
            let email = ::std::str::from_utf8(&email_bytes[..]).unwrap();
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

        if most_common_blocks.len() == 2 {
            let (ref block1, _) = most_common_blocks[0];
            let (ref block2, _) = most_common_blocks[1];
            return (block1.clone(), block2.clone());
        }
        else {
            panic!("couldn't find most common blocks");
        }
    };

    // encrypt:
    // email=..........admin<pcks7 padding>...............&uid=10&role=user
    let calculate_admin_block = |block1: Vec<u8>, block2: Vec<u8>| {
        for _ in 0..1000 {
            let email = "blorg@bar.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b...............";
            let ciphertext = encrypter(email);
            if &ciphertext[48..64] == &block1[..] || &ciphertext[48..64] == &block2[..] {
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

pub fn crack_cbc_bitflipping<F> (f: &F) -> Vec<u8> where F: Fn(&str) -> Vec<u8> {
    let mut ciphertext = f("AAAAAAAAAAAAAAAA:admin<true:AAAA");
    ciphertext[32] = ciphertext[32] ^ 0x01;
    ciphertext[38] = ciphertext[38] ^ 0x01;
    ciphertext[43] = ciphertext[43] ^ 0x01;
    return ciphertext;
}

pub fn crack_cbc_padding_oracle<F> (iv: &[u8], ciphertext: &[u8], f: &F) -> Vec<u8> where F: Fn(&[u8], &[u8]) -> bool {
    let mut prev = iv;
    let mut plaintext = vec![];
    for block in ciphertext.chunks(16) {
        let mut plaintext_block = vec![];
        'BYTE: for byte in 0..16u8 {
            for c_int in 0..256 {
                let c = (255 - c_int) as u8;
                let offset = (16 - byte - 1) as usize;
                let mut iv: Vec<u8> = prev
                    .iter()
                    .take(offset)
                    .map(|x| *x)
                    .collect();
                iv.push(prev[offset] ^ c ^ (byte + 1));
                for i in 0..(byte as usize) {
                    iv.push(prev[offset + i + 1] ^ plaintext_block[i] ^ (byte + 1));
                }
                if f(&iv[..], block) {
                    plaintext_block.insert(0, c);
                    continue 'BYTE;
                }
            }
            panic!("no byte found! ({})", byte);
        }
        for c in plaintext_block {
            plaintext.push(c);
        }
        prev = block;
    }
    return unpad_pkcs7(&plaintext[..]).unwrap().to_vec();
}

pub fn crack_fixed_nonce_ctr_statistically (input: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let min_len = input.iter().map(|line| line.len()).min().unwrap();
    let max_len = input.iter().map(|line| line.len()).max().unwrap();

    let mut plaintext_lines = vec![];
    for _ in input.iter() {
        plaintext_lines.push(vec![]);
    }

    let mut full_key = vec![];
    for len in min_len..(max_len + 1) {
        let mut idxs = vec![];
        let ciphertext: Vec<u8> = input
            .iter()
            .enumerate()
            .filter(|&(idx, line)| {
                if line.len() >= len {
                    idxs.push(idx);
                    true
                }
                else {
                    false
                }
            })
            .flat_map(|(_, line)| line.iter().take(len))
            .map(|x| *x)
            .collect();

        let (key, _) = crack_repeating_key_xor_with_keysize(
            &ciphertext[..],
            len
        );
        for i in full_key.len()..key.len() {
            full_key.push(key[i])
        }

        for idx in idxs {
            let line = repeating_key_xor(&input[idx][..], &full_key[..])
                .iter()
                .take(full_key.len())
                .map(|x| *x)
                .collect();
            plaintext_lines[idx] = line;
        }
    }

    return plaintext_lines;
}

pub fn recover_mersenne_twister_seed_from_time (output: u32) -> Option<u32> {
    let now = ::time::now().to_timespec().sec as u32;
    for i in -10000..10000i32 {
        let seed = (now as i32).wrapping_add(i) as u32;
        let mut mt = MersenneTwister::from_seed(seed);
        let test_output: u32 = mt.gen();
        if test_output == output {
            return Some(seed);
        }
    }
    return None;
}

pub fn clone_mersenne_twister_from_output (outputs: &[u32]) -> MersenneTwister {
    fn untemper (val: u32) -> u32 {
        fn unxorshift<F> (f: F, mut y: u32, n: usize, mask: u32) -> u32 where F: Fn(u32, usize) -> u32 {
            let mut a = y;
            for _ in 0..(32 / n) {
                y = f(y, n) & mask;
                a = a ^ y;
            }
            return a;
        }

        let mut y = val;

        y = unxorshift(|a, n| {a >> n}, y, 18, 0xffffffff);
        y = unxorshift(|a, n| {a << n}, y, 15, 0xefc60000);
        y = unxorshift(|a, n| {a << n}, y,  7, 0x9d2c5680);
        y = unxorshift(|a, n| {a >> n}, y, 11, 0xffffffff);

        y
    }

    let mut state = [0; 624];
    for (i, &output) in outputs.iter().enumerate() {
        state[i] = untemper(output);
    }

    return MersenneTwister::from_seed((state, 0));
}

pub fn recover_16_bit_mt19937_key (ciphertext: &[u8], suffix: &[u8]) -> Option<u16> {
    for _key in 0..65536u32 {
        let key = _key as u16;
        let plaintext = ::random::mt19937_stream_cipher(
            ciphertext,
            key as u32
        );
        if &plaintext[(ciphertext.len() - suffix.len())..] == suffix {
            return Some(key);
        }
    }

    return None;
}

pub fn recover_mt19937_key_from_time (token: &[u8]) -> Option<u32> {
    let now = ::time::now().to_timespec().sec as u32;
    for i in -500..500i32 {
        let seed = (now as i32).wrapping_add(i) as u32;
        let mut mt = MersenneTwister::from_seed(seed);
        let test_token: Vec<u8> = mt.gen_iter().take(16).collect();
        if &test_token[..] == token {
            return Some(seed);
        }
    }
    return None;
}

pub fn crack_aes_128_ctr_random_access<F> (ciphertext: &[u8], edit: F) -> Vec<u8> where F: Fn(&[u8], usize, &[u8]) -> Vec<u8> {
    let empty_plaintext: Vec<u8> = ::std::iter::repeat(b'\x00')
        .take(ciphertext.len())
        .collect();
    let keystream = edit(ciphertext, 0, &empty_plaintext[..]);
    return fixed_xor(&keystream[..], ciphertext);
}

pub fn crack_ctr_bitflipping<F> (f: &F) -> Vec<u8> where F: Fn(&str) -> Vec<u8> {
    let ciphertext = f("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    let replacement = fixed_xor(&ciphertext[32..44], b";admin=true;");
    return ciphertext[..32]
        .iter()
        .chain(replacement.iter())
        .chain(ciphertext[44..].iter())
        .map(|x| *x)
        .collect();
}

pub fn crack_cbc_iv_key<F1, F2> (encrypt: &F1, verify: &F2) -> Vec<u8> where F1: Fn(&str) -> Vec<u8>, F2: Fn(&[u8]) -> Result<bool, Vec<u8>> {
    loop {
        let plaintext_bytes: Vec<u8> = ::rand::thread_rng()
            .gen_iter()
            .filter(|&c| c >= 32 && c < 127)
            .take(16*5)
            .collect();
        let plaintext = ::std::str::from_utf8(&plaintext_bytes).unwrap();
        let ciphertext = encrypt(plaintext);
        let modified_ciphertext: Vec<u8> = ciphertext[..16]
            .iter()
            .map(|x| *x)
            .chain(::std::iter::repeat(0).take(16))
            .chain(ciphertext[..16].iter().map(|x| *x))
            .chain(ciphertext[48..].iter().map(|x| *x))
            .collect();
        if let Err(modified_plaintext) = verify(&modified_ciphertext[..]) {
            let key = fixed_xor(
                &modified_plaintext[..16],
                &modified_plaintext[32..48]
            );
            let desired_plaintext = b"comment1=cooking%20MCs;userdata=;admin=true;comment2=%20like%20a%20pound%20of%20bacon";
            return encrypt_aes_128_cbc(desired_plaintext, &key[..], &key[..]);
        }
    }
}

fn crack_single_byte_xor_with_confidence (input: &[u8]) -> (u8, f64) {
    let mut min_diff = 100.0;
    let mut best_key = 0;
    for a in 0..256u16 {
        let decrypted = fixed_xor(
            input,
            &::std::iter::repeat(a as u8)
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

fn crack_repeating_key_xor_with_keysize (input: &[u8], keysize: usize) -> (Vec<u8>, f64) {
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
    return (key, diff / (keysize as f64));
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
        let prefix: Vec<u8> = ::std::iter::repeat(byte)
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
