use num_bigint::RandBigInt;

#[derive(Debug)]
pub struct DHKeyPair {
    pub p: num_bigint::BigUint,
    pub g: num_bigint::BigUint,
    pub pubkey: num_bigint::BigUint,
    privkey: Option<num_bigint::BigUint>,
}

impl DHKeyPair {
    pub fn new(p: num_bigint::BigUint, g: num_bigint::BigUint) -> DHKeyPair {
        let privkey = rand::thread_rng().gen_biguint_below(&p);
        let pubkey = g.modpow(&privkey, &p);
        DHKeyPair {
            p,
            g,
            pubkey,
            privkey: Some(privkey),
        }
    }

    pub fn key_exchange(
        &self,
        other_pubkey: &num_bigint::BigUint,
    ) -> num_bigint::BigUint {
        other_pubkey.modpow(self.privkey.as_ref().unwrap(), &self.p)
    }
}
