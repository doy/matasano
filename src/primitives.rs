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
