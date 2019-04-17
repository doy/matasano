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
