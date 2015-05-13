#[cfg(test)] use serialize::hex::ToHex;

pub fn sha1 (bytes: &[u8]) -> [u8; 20] {
    sha1_with_state(
        bytes,
        [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
    )
}

pub fn pad_sha1 (bytes: &[u8]) -> Vec<u8> {
    return bytes
        .iter()
        .map(|x| *x)
        .chain(sha1_padding(bytes.len() as u64))
        .collect();
}

pub fn sha1_padding (len: u64) -> Vec<u8> {
    let ml: u64 = len * 8;
    let ml_bytes: [u8; 8] = unsafe {
        ::std::mem::transmute(ml.to_be())
    };
    return [0x80u8]
        .iter()
        .map(|x| *x)
        .chain(::std::iter::repeat(0x00).take(55 - (len % 64) as usize))
        .chain(ml_bytes.iter().map(|x| *x))
        .collect();
}

pub fn sha1_with_state (bytes: &[u8], mut h: [u32; 5]) -> [u8; 20] {
    for chunk in pad_sha1(bytes).chunks(64) {
        let chunk_words: &[u32; 16] = unsafe {
            ::std::mem::transmute(chunk.as_ptr())
        };
        let mut w: [u32; 80] = unsafe { ::std::mem::uninitialized() };
        for i in 0..16 {
            w[i] = u32::from_be(chunk_words[i]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for i in 0..80 {
            let (f, k) = match i {
                0...19  => ((b & c) | (!b & d),          0x5A827999),
                20...39 => (b ^ c ^ d,                   0x6ED9EBA1),
                40...59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60...79 => (b ^ c ^ d,                   0xCA62C1D6),
                _ => panic!(),
            };

            let temp = a.rotate_left(5)
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

    return unsafe { ::std::mem::transmute(h) };
}

pub fn sha1_mac (bytes: &[u8], key: &[u8]) -> [u8; 20] {
    let full_bytes: Vec<u8> = key
        .iter()
        .chain(bytes.iter())
        .map(|x| *x)
        .collect();
    return sha1(&full_bytes[..]);
}

#[test]
fn test_sha1 () {
    let tests = [
        (
            &b""[..],
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ),
        (
            &b"The quick brown fox jumps over the lazy dog"[..],
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        ),
        (
            &b"The quick brown fox jumps over the lazy cog"[..],
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
        ),
    ];
    for &(input, expected) in tests.iter() {
        let got = &sha1(input)[..].to_hex();
        assert_eq!(got, expected);
    }
}
