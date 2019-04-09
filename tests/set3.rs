use rand::{FromEntropy, Rng};
use rustc_serialize::base64::FromBase64;

mod util;

#[test]
fn problem_17() {
    let strings = [
        &b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="[..],
        &b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="[..],
        &b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="[..],
        &b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="[..],
        &b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"[..],
        &b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="[..],
        &b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="[..],
        &b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="[..],
        &b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="[..],
        &b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"[..],
    ];
    let key = util::random_aes_128_key();

    static mut CHOSEN_PLAINTEXT_IDX: usize = 0;
    let encrypter = || {
        let idx = rand::thread_rng().gen_range(0, strings.len());
        let plaintext = strings[idx].from_base64().unwrap();
        unsafe { CHOSEN_PLAINTEXT_IDX = idx };
        let iv = util::random_aes_128_key();
        return (
            iv,
            matasano::encrypt_aes_128_cbc(&plaintext[..], &key[..], &iv[..]),
        );
    };

    let validator = |iv: &[u8], ciphertext: &[u8]| {
        let plaintext =
            matasano::decrypt_aes_128_cbc(ciphertext, &key[..], &iv[..]);
        return plaintext.is_some();
    };

    let (iv, ciphertext) = encrypter();
    for _ in 0..5 {
        let plaintext = matasano::crack_cbc_padding_oracle(
            &iv[..],
            &ciphertext[..],
            &validator,
        );
        let idx = unsafe { CHOSEN_PLAINTEXT_IDX.clone() };
        let expected = strings[idx].from_base64().unwrap();
        assert_eq!(plaintext, expected);
    }
}

#[test]
fn problem_18() {
    let ciphertext = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syL\
                       XzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        .from_base64()
        .unwrap();
    let plaintext =
        &b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "[..];
    let got = matasano::aes_128_ctr(&ciphertext[..], b"YELLOW SUBMARINE", 0);
    assert_eq!(got, plaintext);
}

// #[test]
// fn problem_19 () {
//     let key = util::random_aes_128_key();
//     let ciphertexts = util::read_as_base64_lines("data/19.txt")
//         .iter()
//         .map(|line| matasano::aes_128_ctr(&line[..], &key[..], 0))
//         .collect();
//     let plaintexts = matasano::crack_fixed_nonce_ctr_substitutions();
// }

#[test]
fn problem_20() {
    fn normalize(line_list: Vec<Vec<u8>>, len: usize) -> Vec<Vec<u8>> {
        line_list
            .iter()
            .map(|line| line.to_ascii_lowercase())
            .map(|line| line.iter().take(len).map(|x| *x).collect())
            .collect()
    }

    let key = util::random_aes_128_key();
    let ciphertexts = util::read_as_base64_lines("data/20.txt")
        .iter()
        .map(|line| matasano::aes_128_ctr(&line[..], &key[..], 0))
        .collect();
    let expected = util::read_as_lines("data/20.out.txt");

    let plaintexts =
        matasano::crack_fixed_nonce_ctr_statistically(ciphertexts);

    assert_eq!(normalize(plaintexts, 27), normalize(expected, 27));
}

#[test]
fn problem_21() {
    let mut mt = matasano::MersenneTwister::from_u32(0x12345678);
    let got: Vec<u32> = mt
        .sample_iter(&rand::distributions::Standard)
        .take(10)
        .collect();
    let expected: Vec<u32> = vec![
        0xC6979343, 0x0962D2FA, 0xA73A24A4, 0xE118A180, 0xB5475ABB,
        0x64613C7C, 0x6F32F4DB, 0xF27BF199, 0x464DD8DC, 0x95C1FED6,
    ];
    assert_eq!(&got[..], &expected[..]);
}

#[test]
fn problem_22() {
    // std::thread::sleep_ms(rand::thread_rng().gen_range(40, 1000) * 1000);
    let seed = util::now();
    let mut mt = matasano::MersenneTwister::from_u32(seed);
    // std::thread::sleep_ms(rand::thread_rng().gen_range(40, 1000) * 1000);
    let output: u32 = mt.gen();
    let got =
        matasano::recover_mersenne_twister_seed_from_time(output).unwrap();
    assert_eq!(got, seed);
}

#[test]
fn problem_23() {
    let mut mt = matasano::MersenneTwister::from_entropy();
    let outputs: Vec<u32> = mt
        .sample_iter(&rand::distributions::Standard)
        .take(624)
        .collect();
    let mut mt2 = matasano::clone_mersenne_twister_from_output(&outputs[..]);
    for _ in 1..1000 {
        assert_eq!(mt.gen::<u32>(), mt2.gen::<u32>());
    }
}

#[test]
fn problem_24() {
    let key: u16 = rand::thread_rng().gen();
    let fixed_suffix = b"AAAAAAAAAAAAAA";
    let plaintext: Vec<u8> = rand::thread_rng()
        .sample_iter(&rand::distributions::Standard)
        .take(rand::thread_rng().gen_range(0, 32))
        .chain(fixed_suffix.iter().map(|x| *x))
        .collect();
    let ciphertext =
        matasano::mt19937_stream_cipher(&plaintext[..], key as u32);
    let got = matasano::recover_16_bit_mt19937_key(
        &ciphertext[..],
        &fixed_suffix[..],
    )
    .unwrap();
    assert_eq!(got, key);
}

#[test]
fn problem_24_part_2() {
    let seed = util::now();
    let mut mt = matasano::MersenneTwister::from_u32(seed);
    let token: Vec<u8> = mt
        .sample_iter(&rand::distributions::Standard)
        .take(16)
        .collect();
    let got = matasano::recover_mt19937_key_from_time(&token[..]).unwrap();
    assert_eq!(got, seed);
}
