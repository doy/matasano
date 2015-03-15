extern crate matasano;

#[test]
fn problem_1 () {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(matasano::hex_to_base64(hex), base64);
}

#[test]
fn problem_2 () {
    let str1 = "1c0111001f010100061a024b53535009181c";
    let str2 = "686974207468652062756c6c277320657965";
    let expected = "746865206b696420646f6e277420706c6179";
    assert_eq!(matasano::fixed_xor(str1, str2), expected);
}
