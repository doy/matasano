#[cfg(test)]
use rustc_serialize::hex::ToHex;

use crate::primitives::fixed_xor;

pub fn sha1(bytes: &[u8]) -> [u8; 20] {
    sha1_with_state(
        bytes,
        [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        bytes.len() as u64,
    )
}

pub fn pad_sha1(bytes: &[u8], len: u64) -> Vec<u8> {
    return bytes.iter().map(|x| *x).chain(sha1_padding(len)).collect();
}

pub fn sha1_padding(len: u64) -> Vec<u8> {
    let ml: u64 = len * 8;
    let ml_bytes: [u8; 8] = unsafe { std::mem::transmute(ml.to_be()) };
    return [0x80u8]
        .iter()
        .map(|x| *x)
        .chain(std::iter::repeat(0x00).take((119 - (len % 64) as usize) % 64))
        .chain(ml_bytes.iter().map(|x| *x))
        .collect();
}

pub fn sha1_with_state(bytes: &[u8], mut h: [u32; 5], len: u64) -> [u8; 20] {
    for chunk in pad_sha1(bytes, len).chunks(64) {
        let chunk_words: &[u32; 16] =
            unsafe { std::mem::transmute(chunk.as_ptr()) };
        let mut w: [u32; 80] = unsafe { std::mem::uninitialized() };
        for i in 0..16 {
            w[i] = u32::from_be(chunk_words[i]);
        }
        for i in 16..80 {
            w[i] =
                (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for i in 0..80 {
            let (f, k) = match i {
                0...19 => ((b & c) | (!b & d), 0x5A827999),
                20...39 => (b ^ c ^ d, 0x6ED9EBA1),
                40...59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60...79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => panic!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    for word in h.iter_mut() {
        *word = word.to_be();
    }

    return unsafe { std::mem::transmute(h) };
}

pub fn sha1_mac(bytes: &[u8], key: &[u8]) -> [u8; 20] {
    let full_bytes: Vec<u8> =
        key.iter().chain(bytes.iter()).map(|x| *x).collect();
    return sha1(&full_bytes[..]);
}

pub fn sha1_hmac(bytes: &[u8], key: &[u8]) -> [u8; 20] {
    let blocksize = 64;
    let fixed_key: Vec<u8> = if key.len() > blocksize {
        sha1(key)
            .iter()
            .map(|x| *x)
            .chain(::std::iter::repeat(0x00u8).take(44))
            .collect()
    } else {
        key.iter()
            .map(|x| *x)
            .chain(::std::iter::repeat(0x00u8).take(blocksize - key.len()))
            .collect()
    };

    let ipad: Vec<u8> = std::iter::repeat(0x36u8).take(blocksize).collect();
    let opad: Vec<u8> = std::iter::repeat(0x5cu8).take(blocksize).collect();
    let k_ipad = fixed_xor(&ipad[..], &fixed_key[..]);
    let k_opad = fixed_xor(&opad[..], &fixed_key[..]);

    let inner = sha1(
        &k_ipad
            .iter()
            .chain(bytes.iter())
            .map(|x| *x)
            .collect::<Vec<u8>>()[..],
    );
    return sha1(
        &k_opad
            .iter()
            .chain(inner.iter())
            .map(|x| *x)
            .collect::<Vec<u8>>()[..],
    );
}

#[test]
fn test_sha1() {
    let tests = [
        (&b""[..], "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (
            &b"The quick brown fox jumps over the lazy dog"[..],
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        ),
        (
            &b"The quick brown fox jumps over the lazy cog"[..],
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
        ),
    ];
    for &(input, expected) in tests.iter() {
        let got = &sha1(input)[..].to_hex();
        assert_eq!(got, expected);
    }
}

#[test]
fn test_sha1_hmac() {
    assert_eq!(
        &sha1_hmac(b"", b"")[..].to_hex(),
        "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
    );
    assert_eq!(&sha1_hmac(b"The quick brown fox jumps over the lazy dog", b"key")[..].to_hex(), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}
