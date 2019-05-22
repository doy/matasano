use num_bigint::RandBigInt;
use rand::Rng;
use rayon::prelude::*;
use std::borrow::ToOwned;
use std::collections::{HashMap, HashSet};

use crate::aes::encrypt_aes_128_cbc;
use crate::data::ENGLISH_FREQUENCIES;
use crate::primitives::{fixed_xor, hamming, repeating_key_xor, unpad_pkcs7};
use crate::random::MersenneTwister;

#[derive(PartialEq, Eq, Debug)]
pub enum BlockCipherMode {
    ECB,
    CBC,
}

pub fn find_single_byte_xor_encrypted_string(inputs: &[Vec<u8>]) -> Vec<u8> {
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

pub fn crack_single_byte_xor(input: &[u8]) -> Vec<u8> {
    let (key, _) = crack_single_byte_xor_with_confidence(input);
    return repeating_key_xor(input, &[key]);
}

pub fn crack_repeating_key_xor(input: &[u8]) -> Vec<u8> {
    let mut keysizes = vec![];
    for keysize in 2..40 {
        let distance1 = hamming(
            &input[(keysize * 0)..(keysize * 1)],
            &input[(keysize * 1)..(keysize * 2)],
        ) as f64;
        let distance2 = hamming(
            &input[(keysize * 1)..(keysize * 2)],
            &input[(keysize * 2)..(keysize * 3)],
        ) as f64;
        let distance3 = hamming(
            &input[(keysize * 2)..(keysize * 3)],
            &input[(keysize * 3)..(keysize * 4)],
        ) as f64;
        let distance = distance1 + distance2 + distance3 / 3.0;
        let normal_distance = distance / (keysize as f64);
        keysizes.push((keysize, normal_distance));
        if keysizes.len() > 5 {
            let (idx, _) = keysizes.iter().enumerate().fold(
                (0, (0, 0.0)),
                |(accidx, (accsize, accdist)), (idx, &(size, dist))| {
                    if dist > accdist {
                        (idx, (size, dist))
                    } else {
                        (accidx, (accsize, accdist))
                    }
                },
            );
            keysizes.swap_remove(idx);
        }
    }

    let mut min_diff = 100.0;
    let mut best_key = vec![];
    for (keysize, _) in keysizes {
        let (key, diff) =
            crack_repeating_key_xor_with_keysize(input, keysize);
        if diff < min_diff {
            min_diff = diff;
            best_key = key;
        }
    }

    return best_key;
}

pub fn find_aes_128_ecb_encrypted_string(inputs: &[Vec<u8>]) -> Vec<u8> {
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

pub fn detect_ecb_cbc<F>(f: &F, block_size: usize) -> BlockCipherMode
where
    F: Fn(&[u8]) -> Vec<u8>,
{
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
    } else {
        return BlockCipherMode::CBC;
    }
}

pub fn crack_padded_aes_128_ecb<F>(f: &F) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
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
        } else {
            break;
        }

        i += 1;
    }

    return unpad_pkcs7(&plaintext[..])
        .expect("invalid padding")
        .to_vec();
}

pub fn crack_padded_aes_128_ecb_with_prefix<F>(f: &F) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
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

pub fn crack_querystring_aes_128_ecb<F>(
    encrypter: &F,
) -> (String, Vec<Vec<u8>>)
where
    F: Fn(&str) -> Vec<u8>,
{
    fn incr_map_element(map: &mut HashMap<Vec<u8>, usize>, key: Vec<u8>) {
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
                let (idx, _) = most_common_blocks.iter().enumerate().fold(
                    (0, (vec![], 10000)),
                    |(aidx, (ablock, acount)), (idx, &(ref block, count))| {
                        if count < acount {
                            (idx, (block.clone(), count))
                        } else {
                            (aidx, (ablock.clone(), acount))
                        }
                    },
                );
                most_common_blocks.swap_remove(idx);
            }
        }

        if most_common_blocks.len() == 2 {
            let (ref block1, _) = most_common_blocks[0];
            let (ref block2, _) = most_common_blocks[1];
            return (block1.clone(), block2.clone());
        } else {
            panic!("couldn't find most common blocks");
        }
    };

    // encrypt:
    // email=..........admin<pcks7 padding>...............&uid=10&role=user
    let calculate_admin_block = |block1: Vec<u8>, block2: Vec<u8>| {
        for _ in 0..1000 {
            let email =
                "blorg@bar.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b...............";
            let ciphertext = encrypter(email);
            if &ciphertext[48..64] == &block1[..]
                || &ciphertext[48..64] == &block2[..]
            {
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
            if !possibles
                .iter()
                .any(|possible| possible == &modified_ciphertext)
            {
                possibles.push(modified_ciphertext);
            }
        }
        return (email.to_owned(), possibles);
    };

    let (block1, block2) = find_uid_role_blocks();
    let admin_block = calculate_admin_block(block1, block2);
    return calculate_possible_admin_ciphertexts(admin_block);
}

pub fn crack_cbc_bitflipping<F>(f: &F) -> Vec<u8>
where
    F: Fn(&str) -> Vec<u8>,
{
    let mut ciphertext = f("AAAAAAAAAAAAAAAA:admin<true:AAAA");
    ciphertext[32] = ciphertext[32] ^ 0x01;
    ciphertext[38] = ciphertext[38] ^ 0x01;
    ciphertext[43] = ciphertext[43] ^ 0x01;
    return ciphertext;
}

pub fn crack_cbc_padding_oracle<F>(
    iv: &[u8],
    ciphertext: &[u8],
    f: &F,
) -> Vec<u8>
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    let mut prev = iv;
    let mut plaintext = vec![];
    for block in ciphertext.chunks(16) {
        let mut plaintext_block = vec![];
        'BYTE: for byte in 0..16u8 {
            for c_int in 0..256 {
                let c = (255 - c_int) as u8;
                let offset = (16 - byte - 1) as usize;
                let mut iv: Vec<u8> =
                    prev.iter().take(offset).map(|x| *x).collect();
                iv.push(prev[offset] ^ c ^ (byte + 1));
                for i in 0..(byte as usize) {
                    iv.push(
                        prev[offset + i + 1]
                            ^ plaintext_block[i]
                            ^ (byte + 1),
                    );
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

pub fn crack_fixed_nonce_ctr_statistically(
    input: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
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
                } else {
                    false
                }
            })
            .flat_map(|(_, line)| line.iter().take(len))
            .map(|x| *x)
            .collect();

        let (key, _) =
            crack_repeating_key_xor_with_keysize(&ciphertext[..], len);
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

pub fn recover_mersenne_twister_seed_from_time(output: u32) -> Option<u32> {
    let now = time::now().to_timespec().sec as u32;
    for i in -10000..10000i32 {
        let seed = (now as i32).wrapping_add(i) as u32;
        let mut mt = MersenneTwister::from_u32(seed);
        let test_output: u32 = mt.gen();
        if test_output == output {
            return Some(seed);
        }
    }
    return None;
}

pub fn clone_mersenne_twister_from_output(
    outputs: &[u32],
) -> MersenneTwister {
    fn untemper(val: u32) -> u32 {
        fn unxorshift<F>(f: F, mut y: u32, n: usize, mask: u32) -> u32
        where
            F: Fn(u32, usize) -> u32,
        {
            let mut a = y;
            for _ in 0..(32 / n) {
                y = f(y, n) & mask;
                a = a ^ y;
            }
            return a;
        }

        let mut y = val;

        y = unxorshift(|a, n| a >> n, y, 18, 0xffffffff);
        y = unxorshift(|a, n| a << n, y, 15, 0xefc60000);
        y = unxorshift(|a, n| a << n, y, 7, 0x9d2c5680);
        y = unxorshift(|a, n| a >> n, y, 11, 0xffffffff);

        y
    }

    let mut state = [0; 624];
    for (i, &output) in outputs.iter().enumerate() {
        state[i] = untemper(output);
    }

    return MersenneTwister::from_state(state, 0);
}

pub fn recover_16_bit_mt19937_key(
    ciphertext: &[u8],
    suffix: &[u8],
) -> Option<u16> {
    for _key in 0..65536u32 {
        let key = _key as u16;
        let plaintext =
            crate::random::mt19937_stream_cipher(ciphertext, key as u32);
        if &plaintext[(ciphertext.len() - suffix.len())..] == suffix {
            return Some(key);
        }
    }

    return None;
}

pub fn recover_mt19937_key_from_time(token: &[u8]) -> Option<u32> {
    let now = time::now().to_timespec().sec as u32;
    for i in -500..500i32 {
        let seed = (now as i32).wrapping_add(i) as u32;
        let mut mt = MersenneTwister::from_u32(seed);
        let test_token: Vec<u8> = mt
            .sample_iter(&rand::distributions::Standard)
            .take(16)
            .collect();
        if &test_token[..] == token {
            return Some(seed);
        }
    }
    return None;
}

pub fn crack_aes_128_ctr_random_access<F>(
    ciphertext: &[u8],
    edit: F,
) -> Vec<u8>
where
    F: Fn(&[u8], usize, &[u8]) -> Vec<u8>,
{
    let empty_plaintext: Vec<u8> =
        std::iter::repeat(b'\x00').take(ciphertext.len()).collect();
    let keystream = edit(ciphertext, 0, &empty_plaintext[..]);
    return fixed_xor(&keystream[..], ciphertext);
}

pub fn crack_ctr_bitflipping<F>(f: &F) -> Vec<u8>
where
    F: Fn(&str) -> Vec<u8>,
{
    let ciphertext = f("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    let replacement = fixed_xor(&ciphertext[32..44], b";admin=true;");
    return ciphertext[..32]
        .iter()
        .chain(replacement.iter())
        .chain(ciphertext[44..].iter())
        .map(|x| *x)
        .collect();
}

pub fn crack_cbc_iv_key<F1, F2>(encrypt: &F1, verify: &F2) -> Vec<u8>
where
    F1: Fn(&str) -> Vec<u8>,
    F2: Fn(&[u8]) -> Result<bool, Vec<u8>>,
{
    loop {
        let plaintext_bytes: Vec<u8> = rand::thread_rng()
            .sample_iter(&rand::distributions::Standard)
            .filter(|&c| c >= 32 && c < 127)
            .take(16 * 5)
            .collect();
        let plaintext = std::str::from_utf8(&plaintext_bytes).unwrap();
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
                &modified_plaintext[32..48],
            );
            let desired_plaintext = b"comment1=cooking%20MCs;userdata=;admin=true;comment2=%20like%20a%20pound%20of%20bacon";
            return encrypt_aes_128_cbc(
                desired_plaintext,
                &key[..],
                &key[..],
            );
        }
    }
}

pub fn crack_sha1_mac_length_extension(
    input: &[u8],
    mac: [u8; 20],
    extension: &[u8],
) -> Vec<(Vec<u8>, [u8; 20])> {
    let mut sha1_state: [u32; 5] = unsafe { std::mem::transmute(mac) };
    for word in sha1_state.iter_mut() {
        *word = u32::from_be(*word);
    }

    (0..100)
        .map(|i| {
            let new_input: Vec<u8> = input
                .iter()
                .chain(
                    crate::sha1::sha1_padding(i + input.len() as u64).iter(),
                )
                .chain(extension.iter())
                .map(|x| *x)
                .collect();
            let new_hash = crate::sha1::sha1_with_state(
                extension,
                sha1_state,
                i + new_input.len() as u64,
            );
            (new_input, new_hash)
        })
        .collect()
}

pub fn crack_md4_mac_length_extension(
    input: &[u8],
    mac: [u8; 16],
    extension: &[u8],
) -> Vec<(Vec<u8>, [u8; 16])> {
    let mut md4_state: [u32; 4] = unsafe { std::mem::transmute(mac) };
    for word in md4_state.iter_mut() {
        *word = u32::from_le(*word);
    }

    (0..100)
        .map(|i| {
            let new_input: Vec<u8> = input
                .iter()
                .chain(crate::md4::md4_padding(i + input.len() as u64).iter())
                .chain(extension.iter())
                .map(|x| *x)
                .collect();
            let new_hash = crate::md4::md4_with_state(
                extension,
                md4_state,
                i + new_input.len() as u64,
            );
            (new_input, new_hash)
        })
        .collect()
}

pub fn crack_hmac_timing_basic(
    _data: &str,
    request: impl Fn(&str) -> bool,
) -> Vec<u8> {
    let mut res = [0; 20];

    for idx in 0..20 {
        let mut max_val = 0;
        let mut max_dur = 0;
        for i in 0..256 {
            let now = std::time::Instant::now();
            res[idx] = i as u8;
            if request(&hex::encode(res)) {
                return res.to_vec();
            }
            let dur = now.elapsed().as_micros();
            if dur > max_dur {
                max_dur = dur;
                max_val = i;
            }
        }
        res[idx] = max_val as u8;
    }

    unreachable!()
}

fn crack_hmac_timing_advanced_rec<F>(
    file: &str,
    request: &F,
    key: [u8; 20],
    idx: usize,
    timing_cutoff: u128,
) -> Option<(Vec<(u8, u128)>, [u8; 20])>
where
    F: Sync + Send + Fn(&str) -> bool,
{
    let get_timing_for = |i: u8| {
        let mut key = key.clone();
        key[idx] = i;
        let guess = hex::encode(key);

        let mut params = std::collections::HashMap::new();
        params.insert("file", file.to_string());
        params.insert("signature", guess.to_string());
        let uri = format!(
            "{}{}",
            "http://localhost:9000/?",
            crate::http::create_query_string(&params)
        );

        let start = std::time::Instant::now();
        let success = request(&uri);
        (success, start.elapsed().as_micros())
    };

    let initial_timings: Vec<_> = (0..256)
        .into_par_iter()
        .map(|i| (i as u8, get_timing_for(i as u8)))
        .collect();

    for (i, (success, _)) in initial_timings.iter() {
        if *success {
            let mut key = key.clone();
            key[idx] = *i;
            return Some((vec![], key));
        }
    }

    let (_, (_, min_dur)) = initial_timings
        .iter()
        .cloned()
        .min_by_key(|(_, (_, dur))| *dur)
        .unwrap();

    let mut timings: Vec<_> = (0..256)
        .into_par_iter()
        .map(|i| {
            let (_, (_, mut dur)) = initial_timings[i as usize];
            let mut count = 0;
            while dur > min_dur + 2500 && count < 100 {
                let res = get_timing_for(i as u8);
                dur = res.1;
                count += 1;
            }
            (i as u8, dur)
        })
        .collect();

    timings.par_sort_by_key(|(_, dur)| *dur);

    // eprintln!(
    //     "got timings for byte {} ranging from {} to {} (expected: >{})",
    //     idx, timings[0].1, timings[255].1, timing_cutoff
    // );

    if timings[0].1 < timing_cutoff {
        return None;
    }

    // if idx > 0 {
    //     eprintln!("byte {} confirmed to be {}", idx - 1, key[idx - 1]);
    // }

    for (i, _dur) in timings.iter().rev() {
        let mut new_key = key.clone();
        new_key[idx] = *i;
        // eprintln!("guessing that byte {} is {} (dur {})", idx, i, _dur);
        let rec = crack_hmac_timing_advanced_rec(
            file,
            request,
            new_key,
            idx + 1,
            timings[0].1 + 2500,
        );
        if rec.is_some() {
            return rec;
        }
    }

    unreachable!()
}

pub fn crack_hmac_timing_advanced<F>(file: &str, request: F) -> Vec<u8>
where
    F: Sync + Send + Fn(&str) -> bool,
{
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(3)
        .build()
        .unwrap();

    let key = pool.install(|| {
        let (_, key) =
            crack_hmac_timing_advanced_rec(file, &request, [0; 20], 0, 0)
                .unwrap();
        key
    });

    key.to_vec()
}

pub trait DiffieHellmanMessageExchanger {
    fn a_channel(
        &self,
    ) -> (
        &crossbeam::channel::Sender<Vec<u8>>,
        &crossbeam::channel::Receiver<Vec<u8>>,
    );
    fn b_channel(
        &self,
    ) -> (
        &crossbeam::channel::Sender<Vec<u8>>,
        &crossbeam::channel::Receiver<Vec<u8>>,
    );
}

pub struct NullDiffieHellmanMessageExchanger {
    a_sender: crossbeam::channel::Sender<Vec<u8>>,
    a_recver: crossbeam::channel::Receiver<Vec<u8>>,
    b_sender: crossbeam::channel::Sender<Vec<u8>>,
    b_recver: crossbeam::channel::Receiver<Vec<u8>>,
}

impl NullDiffieHellmanMessageExchanger {
    pub fn new() -> NullDiffieHellmanMessageExchanger {
        let (a_sender, b_recver) = crossbeam::channel::unbounded();
        let (b_sender, a_recver) = crossbeam::channel::unbounded();
        NullDiffieHellmanMessageExchanger {
            a_sender,
            a_recver,
            b_sender,
            b_recver,
        }
    }
}

impl DiffieHellmanMessageExchanger for NullDiffieHellmanMessageExchanger {
    fn a_channel(
        &self,
    ) -> (
        &crossbeam::channel::Sender<Vec<u8>>,
        &crossbeam::channel::Receiver<Vec<u8>>,
    ) {
        (&self.a_sender, &self.a_recver)
    }

    fn b_channel(
        &self,
    ) -> (
        &crossbeam::channel::Sender<Vec<u8>>,
        &crossbeam::channel::Receiver<Vec<u8>>,
    ) {
        (&self.b_sender, &self.b_recver)
    }
}

pub struct ParameterInjectionDiffieHellmanMessageExchanger {
    a_sender: crossbeam::channel::Sender<Vec<u8>>,
    a_recver: crossbeam::channel::Receiver<Vec<u8>>,
    b_sender: crossbeam::channel::Sender<Vec<u8>>,
    b_recver: crossbeam::channel::Receiver<Vec<u8>>,
    thread: std::thread::JoinHandle<Vec<u8>>,
}

impl ParameterInjectionDiffieHellmanMessageExchanger {
    pub fn new<F, G, H>(
        inject_pg: F,
        inject_pubkey: G,
        generate_s: H,
    ) -> ParameterInjectionDiffieHellmanMessageExchanger
    where
        F: 'static
            + Send
            + Fn(
                num_bigint::BigUint,
                num_bigint::BigUint,
            ) -> (num_bigint::BigUint, num_bigint::BigUint),
        G: 'static
            + Send
            + Fn(
                num_bigint::BigUint,
                num_bigint::BigUint,
                num_bigint::BigUint,
            ) -> num_bigint::BigUint,
        H: 'static
            + Send
            + Fn(
                num_bigint::BigUint,
                num_bigint::BigUint,
            ) -> Vec<num_bigint::BigUint>,
    {
        let (a_sender, ma_recver) = crossbeam::channel::unbounded();
        let (ma_sender, b_recver) = crossbeam::channel::unbounded();
        let (b_sender, mb_recver) = crossbeam::channel::unbounded();
        let (mb_sender, a_recver) = crossbeam::channel::unbounded();

        let thread = std::thread::spawn(move || {
            let p_bytes: Vec<u8> = ma_recver.recv().unwrap();
            let p: num_bigint::BigUint =
                serde_json::from_slice(&p_bytes).unwrap();
            let g_bytes: Vec<u8> = ma_recver.recv().unwrap();
            let g: num_bigint::BigUint =
                serde_json::from_slice(&g_bytes).unwrap();

            let (modified_p, modified_g) = inject_pg(p.clone(), g.clone());
            ma_sender
                .send(serde_json::to_vec(&modified_p).unwrap())
                .unwrap();
            ma_sender
                .send(serde_json::to_vec(&modified_g).unwrap())
                .unwrap();

            let p_bytes: Vec<u8> = mb_recver.recv().unwrap();
            let p: num_bigint::BigUint =
                serde_json::from_slice(&p_bytes).unwrap();
            let g_bytes: Vec<u8> = mb_recver.recv().unwrap();
            let g: num_bigint::BigUint =
                serde_json::from_slice(&g_bytes).unwrap();
            mb_sender
                .send(serde_json::to_vec(&modified_p).unwrap())
                .unwrap();
            mb_sender
                .send(serde_json::to_vec(&modified_g).unwrap())
                .unwrap();

            let possible_s =
                generate_s(modified_p.clone(), modified_g.clone());

            let a_bytes: Vec<u8> = ma_recver.recv().unwrap();
            let a_pubkey: num_bigint::BigUint =
                serde_json::from_slice(&a_bytes).unwrap();

            let modified_pubkey_a =
                inject_pubkey(p.clone(), g.clone(), a_pubkey);
            ma_sender
                .send(serde_json::to_vec(&modified_pubkey_a).unwrap())
                .unwrap();

            let b_bytes: Vec<u8> = mb_recver.recv().unwrap();
            let b_pubkey: num_bigint::BigUint =
                serde_json::from_slice(&b_bytes).unwrap();

            let modified_pubkey_b =
                inject_pubkey(p.clone(), g.clone(), b_pubkey);
            mb_sender
                .send(serde_json::to_vec(&modified_pubkey_b).unwrap())
                .unwrap();

            let a_ciphertext = ma_recver.recv().unwrap();
            ma_sender.send(a_ciphertext.clone()).unwrap();
            let a_iv = ma_recver.recv().unwrap();
            ma_sender.send(a_iv.clone()).unwrap();

            let b_ciphertext = mb_recver.recv().unwrap();
            mb_sender.send(b_ciphertext.clone()).unwrap();
            let b_iv = mb_recver.recv().unwrap();
            mb_sender.send(b_iv.clone()).unwrap();

            for s in possible_s {
                let mut aes_key =
                    crate::sha1::sha1(&s.to_bytes_le()).to_vec();
                aes_key.truncate(16);

                let a_plaintext = crate::aes::decrypt_aes_128_cbc(
                    &a_ciphertext,
                    &aes_key,
                    &a_iv,
                );
                if let Some(a_plaintext) = a_plaintext {
                    return a_plaintext;
                }
            }

            unreachable!()
        });

        ParameterInjectionDiffieHellmanMessageExchanger {
            a_sender,
            a_recver,
            b_sender,
            b_recver,
            thread,
        }
    }

    pub fn retrieve_plaintext(self) -> Vec<u8> {
        self.thread.join().unwrap()
    }
}

impl DiffieHellmanMessageExchanger
    for ParameterInjectionDiffieHellmanMessageExchanger
{
    fn a_channel(
        &self,
    ) -> (
        &crossbeam::channel::Sender<Vec<u8>>,
        &crossbeam::channel::Receiver<Vec<u8>>,
    ) {
        (&self.a_sender, &self.a_recver)
    }

    fn b_channel(
        &self,
    ) -> (
        &crossbeam::channel::Sender<Vec<u8>>,
        &crossbeam::channel::Receiver<Vec<u8>>,
    ) {
        (&self.b_sender, &self.b_recver)
    }
}

pub trait SRPClient {
    fn server(&mut self) -> &mut crate::dh::SRPServer;

    fn key_exchange_impl(
        &mut self,
        user: &str,
        pass: &str,
    ) -> (Vec<u8>, Vec<u8>, num_bigint::BigUint);

    fn register(&mut self, user: &str, pass: &str) {
        let n = &self.server().n.clone();
        let g = &self.server().g.clone();

        let mut salt = [0; 16];
        rand::thread_rng().fill(&mut salt);
        let input = [&salt[..], pass.as_bytes()].concat();
        let xh = crate::sha1::sha1(&input);
        let x = num_bigint::BigUint::from_bytes_le(&xh[..]);
        let v = g.modpow(&x, n);
        self.server().register(user, &salt, &v);
    }

    fn key_exchange(
        &mut self,
        user: &str,
        pass: &str,
    ) -> Option<num_bigint::BigUint> {
        let (session, salt, s) = self.key_exchange_impl(user, pass);
        let k = crate::sha1::sha1(&s.to_bytes_le());
        let hmac = crate::sha1::sha1_hmac(&k, &salt);

        if !self.server().verify(session, hmac.to_vec()) {
            return None;
        }

        Some(s)
    }
}

#[derive(Debug)]
pub struct CorrectSRPClient<'a> {
    server: &'a mut crate::dh::SRPServer,
}

impl<'a> CorrectSRPClient<'a> {
    pub fn new(server: &'a mut crate::dh::SRPServer) -> CorrectSRPClient<'a> {
        CorrectSRPClient { server }
    }
}

impl<'a> SRPClient for CorrectSRPClient<'a> {
    fn server(&mut self) -> &mut crate::dh::SRPServer {
        self.server
    }

    fn key_exchange_impl(
        &mut self,
        user: &str,
        pass: &str,
    ) -> (Vec<u8>, Vec<u8>, num_bigint::BigUint) {
        let n = &self.server.n.clone();
        let g = &self.server.g.clone();
        let k = &self.server.k.clone();

        let a_priv = rand::thread_rng().gen_biguint_below(n);
        let a_pub = g.modpow(&a_priv, n);
        let (session, salt, b_pub) =
            self.server.exchange_pubkeys(user, &a_pub);

        let uinput = [a_pub.to_bytes_le(), b_pub.to_bytes_le()].concat();
        let uh = crate::sha1::sha1(&uinput);
        let u = num_bigint::BigUint::from_bytes_le(&uh[..]);

        let xinput = [salt.clone(), pass.as_bytes().to_vec()].concat();
        let xh = crate::sha1::sha1(&xinput);
        let x = num_bigint::BigUint::from_bytes_le(&xh[..]);

        let s = (b_pub - k * g.modpow(&x, n)).modpow(&(a_priv + u * x), n);

        (session, salt, s)
    }
}

#[derive(Debug)]
pub struct ZeroKeySRPClient<'a> {
    server: &'a mut crate::dh::SRPServer,
}

impl<'a> ZeroKeySRPClient<'a> {
    pub fn new(server: &'a mut crate::dh::SRPServer) -> ZeroKeySRPClient<'a> {
        ZeroKeySRPClient { server }
    }
}

impl<'a> SRPClient for ZeroKeySRPClient<'a> {
    fn server(&mut self) -> &mut crate::dh::SRPServer {
        self.server
    }

    fn key_exchange_impl(
        &mut self,
        user: &str,
        _: &str,
    ) -> (Vec<u8>, Vec<u8>, num_bigint::BigUint) {
        let a_pub = num_bigint::BigUint::from(0 as u8);
        let (session, salt, _b_pub) =
            self.server.exchange_pubkeys(user, &a_pub);

        let s = num_bigint::BigUint::from(0 as u8);
        (session, salt, s)
    }
}

fn crack_single_byte_xor_with_confidence(input: &[u8]) -> (u8, f64) {
    let mut min_diff = 100.0;
    let mut best_key = 0;
    for a in 0..256u16 {
        let decrypted = fixed_xor(
            input,
            &::std::iter::repeat(a as u8)
                .take(input.len())
                .collect::<Vec<u8>>()[..],
        );
        if !decrypted.is_ascii() {
            continue;
        }
        if decrypted
            .iter()
            .any(|&c| c != b'\n' && (c < 0x20 || c > 0x7E))
        {
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
            } else {
                extra_frequencies += 1;
            }
        }

        let mut total_diff = 0.0;
        for (&english, &crypt) in
            ENGLISH_FREQUENCIES.iter().zip(frequencies.iter())
        {
            let relative_frequency =
                (crypt as f64) / (total_frequency as f64);
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

fn crack_repeating_key_xor_with_keysize(
    input: &[u8],
    keysize: usize,
) -> (Vec<u8>, f64) {
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
    let key = cracked.iter().map(|&(c, _)| c).collect();
    return (key, diff / (keysize as f64));
}

fn count_duplicate_blocks(input: &[u8], block_size: usize) -> usize {
    let mut set = HashSet::new();
    let mut dups = 0;
    for block in input.chunks(block_size) {
        if !set.insert(block) {
            dups += 1;
        }
    }
    return dups;
}

fn find_block_size<F>(f: &F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let (block_size, _) = find_block_size_and_fixed_prefix_len(f);
    return block_size;
}

fn find_block_size_and_fixed_prefix_len<F>(f: &F) -> (usize, usize)
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let fixed_prefix_len = find_fixed_block_prefix_len(f);
    let byte = b'A';
    let mut prev = f(&[b'f']);
    let mut len = 0;
    loop {
        let prefix: Vec<u8> = std::iter::repeat(byte).take(len).collect();
        let next = f(&prefix[..]);

        let prefix_len = shared_prefix_len(prev.iter(), next.iter());
        if prefix_len > fixed_prefix_len {
            let block_size = prefix_len - fixed_prefix_len;
            return (block_size, fixed_prefix_len + block_size - (len - 1));
        }

        prev = next;
        len += 1;
    }
}

fn find_fixed_block_prefix_len<F>(f: &F) -> usize
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let ciphertext1 = f(b"");
    let ciphertext2 = f(b"A");
    return shared_prefix_len(ciphertext1.iter(), ciphertext2.iter());
}

fn shared_prefix_len<I>(i1: I, i2: I) -> usize
where
    I: Iterator,
    <I as Iterator>::Item: PartialEq,
{
    return i1.zip(i2).take_while(|&(ref c1, ref c2)| c1 == c2).count();
}
