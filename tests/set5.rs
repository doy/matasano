use matasano::SRPClient;
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

    let plaintext = b"Summertime and the wind is blowing outside in \
                      lower Chelsea and I don't know what I'm doing \
                      in the city, the sun is always in my eyes";

    let null_exchanger = matasano::NullDiffieHellmanMessageExchanger::new();
    run_dh_message_exchange(&null_exchanger, &p, &g, &plaintext[..]);

    let parameter_injection_exchanger =
        matasano::ParameterInjectionDiffieHellmanMessageExchanger::new(
            |p, g| (p, g),
            |p, _, _| p,
            |_, _| vec![num_bigint::BigUint::from(0 as u8)],
        );
    run_dh_message_exchange(
        &parameter_injection_exchanger,
        &p,
        &g,
        &plaintext[..],
    );
    assert_eq!(
        parameter_injection_exchanger.retrieve_plaintext(),
        plaintext.to_vec(),
    );
}

#[test]
fn problem_35() {
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

    let plaintext = b"Summertime and the wind is blowing outside in \
                      lower Chelsea and I don't know what I'm doing \
                      in the city, the sun is always in my eyes";

    let parameter_injection_exchanger_g_1 =
        matasano::ParameterInjectionDiffieHellmanMessageExchanger::new(
            |p, _| (p, num_bigint::BigUint::from(1 as u8)),
            |_, _, pubkey| pubkey,
            |_, _| vec![num_bigint::BigUint::from(1 as u8)],
        );
    run_dh_message_exchange(
        &parameter_injection_exchanger_g_1,
        &p,
        &g,
        &plaintext[..],
    );
    assert_eq!(
        parameter_injection_exchanger_g_1.retrieve_plaintext(),
        plaintext.to_vec(),
    );

    let parameter_injection_exchanger_g_p =
        matasano::ParameterInjectionDiffieHellmanMessageExchanger::new(
            |p, _| (p.clone(), p),
            |_, _, pubkey| pubkey,
            |_, _| vec![num_bigint::BigUint::from(0 as u8)],
        );
    run_dh_message_exchange(
        &parameter_injection_exchanger_g_p,
        &p,
        &g,
        &plaintext[..],
    );
    assert_eq!(
        parameter_injection_exchanger_g_p.retrieve_plaintext(),
        plaintext.to_vec(),
    );

    let parameter_injection_exchanger_g_p_minus_1 =
        matasano::ParameterInjectionDiffieHellmanMessageExchanger::new(
            |p, _| (p.clone(), p - 1u8),
            |_, _, pubkey| pubkey,
            |p, _| vec![num_bigint::BigUint::from(1 as u8), p - 1u8],
        );
    run_dh_message_exchange(
        &parameter_injection_exchanger_g_p_minus_1,
        &p,
        &g,
        &plaintext[..],
    );
    assert_eq!(
        parameter_injection_exchanger_g_p_minus_1.retrieve_plaintext(),
        plaintext.to_vec(),
    );
}

fn run_dh_message_exchange<T>(
    exchanger: &T,
    p: &num_bigint::BigUint,
    g: &num_bigint::BigUint,
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
            a_sender.send(serde_json::to_vec(p).unwrap()).unwrap();
            a_sender.send(serde_json::to_vec(g).unwrap()).unwrap();
            let p_bytes = a_recver.recv().unwrap();
            let negotiated_p: num_bigint::BigUint =
                serde_json::from_slice(&p_bytes).unwrap();
            let g_bytes = a_recver.recv().unwrap();
            let negotiated_g: num_bigint::BigUint =
                serde_json::from_slice(&g_bytes).unwrap();
            let a = matasano::DHKeyPair::new(
                negotiated_p.clone(),
                negotiated_g.clone(),
            );

            a_sender
                .send(serde_json::to_vec(&a.pubkey).unwrap())
                .unwrap();
            let b_bytes = a_recver.recv().unwrap();
            let b_pubkey: num_bigint::BigUint =
                serde_json::from_slice(&b_bytes).unwrap();
            let s = a.key_exchange(&b_pubkey);

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
            let p_bytes = b_recver.recv().unwrap();
            let p: num_bigint::BigUint =
                serde_json::from_slice(&p_bytes).unwrap();
            let g_bytes = b_recver.recv().unwrap();
            let g: num_bigint::BigUint =
                serde_json::from_slice(&g_bytes).unwrap();
            b_sender.send(serde_json::to_vec(&p).unwrap()).unwrap();
            b_sender.send(serde_json::to_vec(&g).unwrap()).unwrap();

            let b = matasano::DHKeyPair::new(p.clone(), g.clone());
            b_sender
                .send(serde_json::to_vec(&b.pubkey).unwrap())
                .unwrap();
            let a_bytes = b_recver.recv().unwrap();
            let a_pubkey: num_bigint::BigUint =
                serde_json::from_slice(&a_bytes).unwrap();
            let s = b.key_exchange(&a_pubkey);

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

#[test]
fn problem_36() {
    let n_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff";
    let n = num_bigint::BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
    let g = num_bigint::BigUint::from(2 as u8);
    let k = num_bigint::BigUint::from(3 as u8);

    let user = "doy@tozt.net";
    let pass = "supersecret";

    let mut server = matasano::SRPServer::new(n, g, k);
    let mut client = matasano::CorrectSRPClient::new(&mut server);

    client.register(user, pass);

    let key = client.key_exchange(user, pass);

    assert!(key.is_some());
}
