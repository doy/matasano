extern crate matasano;
extern crate rand;

use rand::Rng;

mod util;

#[test]
fn problem_25 () {
    let key = util::random_aes_128_key();
    let nonce: u64 = rand::thread_rng().gen();
    let plaintext = util::read("data/25.txt");

    let ciphertext = matasano::aes_128_ctr(&plaintext[..], &key[..], nonce);
    let edit = |ciphertext: &[u8], offset: usize, newtext: &[u8]| {
        let block_start_number = offset / 16;
        let block_start = block_start_number * 16;
        let block_end_number = (offset + newtext.len() - 1) / 16;
        let block_end = std::cmp::min(
            (block_end_number + 1) * 16,
            ciphertext.len()
        );
        let mut plaintext = matasano::aes_128_ctr_with_counter(
            &ciphertext[block_start..block_end],
            &key[..],
            nonce,
            (offset / 16) as u64
        );
        for i in 0..newtext.len() {
            plaintext[offset - block_start + i] = newtext[i];
        }
        let new_ciphertext = matasano::aes_128_ctr_with_counter(
            &plaintext[..],
            &key[..],
            nonce,
            (offset / 16) as u64
        );

        return ciphertext
            .iter()
            .take(block_start)
            .chain(new_ciphertext.iter())
            .chain(ciphertext.iter().skip(block_end))
            .map(|x| *x)
            .collect();
    };

    let got = matasano::crack_aes_128_ctr_random_access(&ciphertext[..], edit);
    assert_eq!(&got[..], &plaintext[..]);
}

#[test]
fn problem_26 () {
    let key = util::random_aes_128_key();
    let nonce = rand::thread_rng().gen();
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let admin = ";admin=true;";

    let escape = |input: &str| {
        input.replace("%", "%25").replace(";", "%3B").replace("=", "%3D")
    };

    let encode = |input: &str| -> Vec<u8> {
        let plaintext: Vec<u8> = prefix
            .as_bytes()
            .iter()
            .chain(escape(input).as_bytes().iter())
            .chain(suffix.as_bytes().iter())
            .map(|x| *x)
            .collect();
        return matasano::aes_128_ctr(&plaintext[..], &key[..], nonce);
    };

    let verify = |ciphertext: &[u8]| -> bool {
        let plaintext = matasano::aes_128_ctr(ciphertext, &key[..], nonce);
        return (0..(plaintext.len() - admin.len())).any(|i| {
            plaintext
                .iter()
                .skip(i)
                .zip(admin.as_bytes().iter())
                .all(|(&c1, &c2)| c1 == c2)
        });
    };

    let ciphertext = matasano::crack_ctr_bitflipping(&encode);
    assert!(verify(&ciphertext[..]));
}

#[test]
fn problem_27 () {
    let key = util::random_aes_128_key();
    let iv = key;
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let admin = ";admin=true;";

    let escape = |input: &str| {
        input.replace("%", "%25").replace(";", "%3B").replace("=", "%3D")
    };

    let encode = |input: &str| -> Vec<u8> {
        let plaintext: Vec<u8> = prefix
            .as_bytes()
            .iter()
            .chain(escape(input).as_bytes().iter())
            .chain(suffix.as_bytes().iter())
            .map(|x| *x)
            .collect();
        return matasano::encrypt_aes_128_cbc(&plaintext[..], &key[..], &iv[..]);
    };

    let verify = |ciphertext: &[u8]| -> Result<bool, Vec<u8>> {
        let plaintext = matasano::decrypt_aes_128_cbc(ciphertext, &key[..], &iv[..]).unwrap();
        if plaintext.iter().any(|&c| c < 32 || c > 126) {
            return Err(plaintext);
        }
        else {
            return Ok(
                (0..(plaintext.len() - admin.len())).any(|i| {
                    plaintext
                        .iter()
                        .skip(i)
                        .zip(admin.as_bytes().iter())
                        .all(|(&c1, &c2)| c1 == c2)
                })
            );
        }
    };

    let ciphertext = matasano::crack_cbc_iv_key(&encode, &verify);
    assert!(verify(&ciphertext[..]).unwrap());
}

// problem 28 is just matasano::sha1_mac
