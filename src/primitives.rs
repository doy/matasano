use std;

pub fn fixed_xor (bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    return bytes1.iter()
        .zip(bytes2.iter())
        .map(|(&a, &b)| { a ^ b })
        .collect();
}

pub fn repeating_key_xor (plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    return fixed_xor(
        plaintext,
        &key
            .iter()
            .cycle()
            .take(plaintext.len())
            .map(|c| *c)
            .collect::<Vec<u8>>()[..]
    );
}

pub fn hamming (bytes1: &[u8], bytes2: &[u8]) -> u64 {
    count_bits(&fixed_xor(bytes1, bytes2)[..])
}

pub fn pad_pkcs7 (block: &[u8], blocksize: u8) -> Vec<u8> {
    let padding_bytes = blocksize - (block.len() % blocksize as usize) as u8;
    return block
        .iter()
        .map(|c| *c)
        .chain(std::iter::repeat(padding_bytes).take(padding_bytes as usize))
        .collect();
}

pub fn unpad_pkcs7 (block: &[u8]) -> &[u8] {
    let padding_byte = block[block.len() - 1];
    return &block[..(block.len() - padding_byte as usize)];
}

fn count_bits (bytes: &[u8]) -> u64 {
    bytes.iter().map(|&c| { count_bits_byte(c) }).fold(0, |acc, n| acc + n)
}

fn count_bits_byte (byte: u8) -> u64 {
    (((byte & (0x01 << 0)) >> 0)
    + ((byte & (0x01 << 1)) >> 1)
    + ((byte & (0x01 << 2)) >> 2)
    + ((byte & (0x01 << 3)) >> 3)
    + ((byte & (0x01 << 4)) >> 4)
    + ((byte & (0x01 << 5)) >> 5)
    + ((byte & (0x01 << 6)) >> 6)
    + ((byte & (0x01 << 7)) >> 7)) as u64
}

#[test]
fn test_hamming () {
    assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
}
