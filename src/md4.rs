#[cfg(test)]
use rustc_serialize::hex::ToHex;

pub fn md4(bytes: &[u8]) -> [u8; 16] {
    md4_with_state(
        bytes,
        [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
        bytes.len() as u64,
    )
}

pub fn pad_md4(bytes: &[u8], len: u64) -> Vec<u8> {
    return bytes.iter().map(|x| *x).chain(md4_padding(len)).collect();
}

pub fn md4_padding(len: u64) -> Vec<u8> {
    let ml: u64 = len * 8;
    let ml_bytes: [u8; 8] = unsafe { std::mem::transmute(ml.to_le()) };
    return [0x80u8]
        .iter()
        .map(|x| *x)
        .chain(std::iter::repeat(0x00).take((119 - (len % 64) as usize) % 64))
        .chain(ml_bytes.iter().map(|x| *x))
        .collect();
}

fn round1(offset: u32, x: u32, s: u32, h: &mut [u32; 4]) {
    let a = (4 - offset as usize) % 4;
    let b = (5 - offset as usize) % 4;
    let c = (6 - offset as usize) % 4;
    let d = (7 - offset as usize) % 4;

    h[a] = h[a]
        .wrapping_add((h[b] & h[c]) | (!h[b] & h[d]))
        .wrapping_add(x)
        .rotate_left(s)
}

fn round2(offset: u32, x: u32, s: u32, h: &mut [u32; 4]) {
    let a = (4 - offset as usize) % 4;
    let b = (5 - offset as usize) % 4;
    let c = (6 - offset as usize) % 4;
    let d = (7 - offset as usize) % 4;

    h[a] = h[a]
        .wrapping_add((h[b] & h[c]) | (h[b] & h[d]) | (h[c] & h[d]))
        .wrapping_add(x)
        .wrapping_add(0x5A827999)
        .rotate_left(s)
}

fn round3(offset: u32, x: u32, s: u32, h: &mut [u32; 4]) {
    let a = (4 - offset as usize) % 4;
    let b = (5 - offset as usize) % 4;
    let c = (6 - offset as usize) % 4;
    let d = (7 - offset as usize) % 4;

    h[a] = h[a]
        .wrapping_add(h[b] ^ h[c] ^ h[d])
        .wrapping_add(x)
        .wrapping_add(0x6ED9EBA1)
        .rotate_left(s)
}

pub fn md4_with_state(bytes: &[u8], mut h: [u32; 4], len: u64) -> [u8; 16] {
    for chunk in pad_md4(bytes, len).chunks(64) {
        let chunk_words: &[u32; 16] =
            unsafe { std::mem::transmute(chunk.as_ptr()) };
        let mut x: [u32; 16] = unsafe { std::mem::uninitialized() };
        for i in 0..16 {
            x[i] = u32::from_le(chunk_words[i]);
        }

        let mut hh = h;

        round1(0, x[0], 3, &mut hh);
        round1(1, x[1], 7, &mut hh);
        round1(2, x[2], 11, &mut hh);
        round1(3, x[3], 19, &mut hh);
        round1(0, x[4], 3, &mut hh);
        round1(1, x[5], 7, &mut hh);
        round1(2, x[6], 11, &mut hh);
        round1(3, x[7], 19, &mut hh);
        round1(0, x[8], 3, &mut hh);
        round1(1, x[9], 7, &mut hh);
        round1(2, x[10], 11, &mut hh);
        round1(3, x[11], 19, &mut hh);
        round1(0, x[12], 3, &mut hh);
        round1(1, x[13], 7, &mut hh);
        round1(2, x[14], 11, &mut hh);
        round1(3, x[15], 19, &mut hh);

        round2(0, x[0], 3, &mut hh);
        round2(1, x[4], 5, &mut hh);
        round2(2, x[8], 9, &mut hh);
        round2(3, x[12], 13, &mut hh);
        round2(0, x[1], 3, &mut hh);
        round2(1, x[5], 5, &mut hh);
        round2(2, x[9], 9, &mut hh);
        round2(3, x[13], 13, &mut hh);
        round2(0, x[2], 3, &mut hh);
        round2(1, x[6], 5, &mut hh);
        round2(2, x[10], 9, &mut hh);
        round2(3, x[14], 13, &mut hh);
        round2(0, x[3], 3, &mut hh);
        round2(1, x[7], 5, &mut hh);
        round2(2, x[11], 9, &mut hh);
        round2(3, x[15], 13, &mut hh);

        round3(0, x[0], 3, &mut hh);
        round3(1, x[8], 9, &mut hh);
        round3(2, x[4], 11, &mut hh);
        round3(3, x[12], 15, &mut hh);
        round3(0, x[2], 3, &mut hh);
        round3(1, x[10], 9, &mut hh);
        round3(2, x[6], 11, &mut hh);
        round3(3, x[14], 15, &mut hh);
        round3(0, x[1], 3, &mut hh);
        round3(1, x[9], 9, &mut hh);
        round3(2, x[5], 11, &mut hh);
        round3(3, x[13], 15, &mut hh);
        round3(0, x[3], 3, &mut hh);
        round3(1, x[11], 9, &mut hh);
        round3(2, x[7], 11, &mut hh);
        round3(3, x[15], 15, &mut hh);

        h[0] = h[0].wrapping_add(hh[0]);
        h[1] = h[1].wrapping_add(hh[1]);
        h[2] = h[2].wrapping_add(hh[2]);
        h[3] = h[3].wrapping_add(hh[3]);
    }

    for word in h.iter_mut() {
        *word = word.to_le();
    }

    return unsafe { std::mem::transmute(h) };
}

pub fn md4_mac(bytes: &[u8], key: &[u8]) -> [u8; 16] {
    let full_bytes: Vec<u8> =
        key.iter().chain(bytes.iter()).map(|x| *x).collect();
    return md4(&full_bytes[..]);
}

#[test]
fn test_md4() {
    let tests = [
        (
            &b""[..],
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        ),
        (
            &b"The quick brown fox jumps over the lazy dog"[..],
            "1bee69a46ba811185c194762abaeae90"
        ),
        (
            &b"The quick brown fox jumps over the lazy cog"[..],
            "b86e130ce7028da59e672d56ad0113df"
        ),
        (
            &b"a"[..],
            "bde52cb31de33e46245e05fbdbd6fb24"
        ),
        (
            &b"abc"[..],
            "a448017aaf21d8525fc10ae87aa6729d"
        ),
        (
            &b"message digest"[..],
            "d9130a8164549fe818874806e1c7014b"
        ),
        (
            &b"abcdefghijklmnopqrstuvwxyz"[..],
            "d79e1c308aa5bbcdeea8ed63df412da9"
        ),
        (
            &b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[..],
            "043f8582f241db351ce627e153e7f0e4"
        ),
        (
            &b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"[..],
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        ),
    ];
    for &(input, expected) in tests.iter() {
        println!("{:?}", input);
        let got = &md4(input)[..].to_hex();
        assert_eq!(got, expected);
    }
}
