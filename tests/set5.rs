use rand::Rng;

#[test]
fn problem_33() {
    let p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff";
    let p = num_bigint::BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap();
    let g = num_bigint::BigUint::from(2 as u8);

    let a = matasano::DHKeyPair::new(p.clone(), g.clone());
    let b = matasano::DHKeyPair::new(p.clone(), g.clone());

    let s1 = a.key_exchange(&b.pubkey);
    let s2 = b.key_exchange(&a.pubkey);

    assert_eq!(s1, s2);
}

#[test]
fn problem_34() {
    let p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff";
    let p = num_bigint::BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap();
    let g = num_bigint::BigUint::from(2 as u8);

    let a = matasano::DHKeyPair::new(p.clone(), g.clone());
    let b = matasano::DHKeyPair::new(p.clone(), g.clone());

    let plaintext = b"Summertime and the wind is blowing outside in \
                      lower Chelsea and I don't know what I'm doing \
                      in the city, the sun is always in my eyes";

    let null_exchanger = matasano::NullDiffieHellmanMessageExchanger::new();
    run_dh_message_exchange(&null_exchanger, &a, &b, &plaintext[..]);

    let parameter_injection_exchanger =
        matasano::ParameterInjectionDiffieHellmanMessageExchanger::new();
    run_dh_message_exchange(
        &parameter_injection_exchanger,
        &a,
        &b,
        &plaintext[..],
    );
    assert_eq!(
        parameter_injection_exchanger.retrieve_plaintext(),
        plaintext.to_vec(),
    );
}

fn run_dh_message_exchange<T>(
    exchanger: &T,
    a: &matasano::DHKeyPair,
    b: &matasano::DHKeyPair,
    plaintext: &[u8],
) where
    T: matasano::DiffieHellmanMessageExchanger,
{
    crossbeam::thread::scope(|s| {
        let (a_sender, a_recver) = exchanger.a_channel();
        let (b_sender, b_recver) = exchanger.b_channel();

        let (key_compare_sender_a, key_compare_recver) =
            crossbeam::channel::unbounded();
        let key_compare_sender_b = key_compare_sender_a.clone();

        let a_runner = s.spawn(move |_| {
            a_sender.send(serde_json::to_vec(a).unwrap()).unwrap();
            let b_bytes = a_recver.recv().unwrap();
            let b: matasano::DHKeyPair =
                serde_json::from_slice(&b_bytes).unwrap();
            let s = a.key_exchange(&b.pubkey);

            let mut aes_key = matasano::sha1(&s.to_bytes_le()).to_vec();
            aes_key.truncate(16);
            key_compare_sender_a.send(aes_key.clone()).unwrap();
            let mut iv = [0; 16];
            rand::thread_rng().fill(&mut iv);

            let ciphertext =
                matasano::encrypt_aes_128_cbc(plaintext, &aes_key, &iv);
            a_sender.send(ciphertext.clone()).unwrap();
            a_sender.send(iv.to_vec()).unwrap();
            let b_ciphertext = a_recver.recv().unwrap();
            let b_iv = a_recver.recv().unwrap();
            let b_plaintext =
                matasano::decrypt_aes_128_cbc(&b_ciphertext, &aes_key, &b_iv)
                    .unwrap();

            assert_eq!(&plaintext[..], b_plaintext.as_slice());
            assert_ne!(&iv[..], b_iv.as_slice());
            assert_ne!(ciphertext, b_ciphertext);
        });
        let b_runner = s.spawn(move |_| {
            b_sender.send(serde_json::to_vec(b).unwrap()).unwrap();
            let a_bytes = b_recver.recv().unwrap();
            let a: matasano::DHKeyPair =
                serde_json::from_slice(&a_bytes).unwrap();
            let s = b.key_exchange(&a.pubkey);

            let mut aes_key = matasano::sha1(&s.to_bytes_le()).to_vec();
            aes_key.truncate(16);
            key_compare_sender_b.send(aes_key.clone()).unwrap();
            let mut iv = [0; 16];
            rand::thread_rng().fill(&mut iv);

            let a_ciphertext = b_recver.recv().unwrap();
            let a_iv = b_recver.recv().unwrap();
            let a_plaintext =
                matasano::decrypt_aes_128_cbc(&a_ciphertext, &aes_key, &a_iv)
                    .unwrap();
            let ciphertext =
                matasano::encrypt_aes_128_cbc(&a_plaintext, &aes_key, &iv);
            b_sender.send(ciphertext.clone()).unwrap();
            b_sender.send(iv.to_vec()).unwrap();
        });

        let key1 = key_compare_recver.recv().unwrap();
        let key2 = key_compare_recver.recv().unwrap();
        assert_eq!(key1, key2);

        a_runner.join().unwrap();
        b_runner.join().unwrap();
    })
    .unwrap();
}
