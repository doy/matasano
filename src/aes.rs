use crate::primitives::{fixed_xor, pad_pkcs7, unpad_pkcs7};

fn decrypt_aes_128_ecb_nopad(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let t = openssl::symm::Cipher::aes_128_ecb();
    let mut c = openssl::symm::Crypter::new(
        t,
        openssl::symm::Mode::Decrypt,
        key,
        None,
    )
    .unwrap();
    c.pad(false);
    let mut out = vec![0; bytes.len() + t.block_size()];
    let count = c.update(bytes, &mut out).unwrap();
    let rest = c.finalize(&mut out[count..]).unwrap();
    out.truncate(count + rest);
    out
}

pub fn decrypt_aes_128_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    return openssl::symm::decrypt(
        openssl::symm::Cipher::aes_128_ecb(),
        key,
        None,
        bytes,
    )
    .unwrap();
}

pub fn decrypt_aes_128_cbc(
    bytes: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Option<Vec<u8>> {
    let mut prev = iv.clone();
    let mut plaintext = vec![];
    for block in bytes.chunks(16) {
        let plaintext_block =
            fixed_xor(&decrypt_aes_128_ecb_nopad(&block, key)[..], prev);
        for c in plaintext_block {
            plaintext.push(c);
        }
        prev = block.clone();
    }
    return unpad_pkcs7(&plaintext[..]).map(|v| v.to_vec());
}

pub fn encrypt_aes_128_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    return openssl::symm::encrypt(
        openssl::symm::Cipher::aes_128_ecb(),
        key,
        None,
        bytes,
    )
    .unwrap();
}

pub fn encrypt_aes_128_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv.to_vec();
    let mut ciphertext = vec![];
    for block in pad_pkcs7(bytes, 16).chunks(16) {
        let plaintext_block = fixed_xor(&block[..], &prev[..]);
        let mut ciphertext_block =
            encrypt_aes_128_ecb(&plaintext_block[..], key);
        ciphertext_block.truncate(16);
        for &c in ciphertext_block.iter() {
            ciphertext.push(c);
        }
        prev = ciphertext_block.clone();
    }
    return ciphertext;
}

pub fn aes_128_ctr(bytes: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    aes_128_ctr_with_counter(bytes, key, nonce, 0)
}

pub fn aes_128_ctr_with_counter(
    bytes: &[u8],
    key: &[u8],
    nonce: u64,
    counter_start: u64,
) -> Vec<u8> {
    let nonce_array: [u8; 8] = unsafe { std::mem::transmute(nonce.to_le()) };
    let mut counter = counter_start;
    let mut ret = vec![];
    for block in bytes.chunks(16) {
        let counter_array: [u8; 8] =
            unsafe { std::mem::transmute(counter.to_le()) };
        let keystream = encrypt_aes_128_ecb(
            &pad_pkcs7(
                &nonce_array
                    .iter()
                    .chain(counter_array.iter())
                    .map(|x| *x)
                    .collect::<Vec<u8>>()[..],
                16,
            )[..],
            key,
        );
        for c in fixed_xor(block, &keystream[..]) {
            ret.push(c);
        }
        counter += 1;
    }
    return ret;
}

#[test]
fn test_encrypt_decrypt() {
    let plaintext = b"Summertime and the wind is blowing outside in lower \
                     Chelsea and I don't know what I'm doing in the city, the \
                     sun is always in my eyes";
    let key = b"YELLOW SUBMARINE";
    let iv = [0; 16];

    let ciphertext_ecb = encrypt_aes_128_ecb(&plaintext[..], &key[..]);
    let ciphertext_cbc =
        encrypt_aes_128_cbc(&plaintext[..], &key[..], &iv[..]);

    let plaintext2_ecb = decrypt_aes_128_ecb(&ciphertext_ecb[..], &key[..]);
    let plaintext2_cbc =
        decrypt_aes_128_cbc(&ciphertext_cbc[..], &key[..], &iv[..]).unwrap();

    let ciphertext2_ecb = encrypt_aes_128_ecb(&plaintext2_ecb[..], &key[..]);
    let ciphertext2_cbc =
        encrypt_aes_128_cbc(&plaintext2_cbc[..], &key[..], &iv[..]);

    assert_eq!(&plaintext[..], &plaintext2_ecb[..]);
    assert_eq!(&plaintext[..], &plaintext2_cbc[..]);
    assert_eq!(&ciphertext_ecb[..], &ciphertext2_ecb[..]);
    assert_eq!(&ciphertext_cbc[..], &ciphertext2_cbc[..]);
}
