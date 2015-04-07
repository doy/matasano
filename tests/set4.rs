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
