use num_bigint::RandBigInt;
use rand::Rng;

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

#[derive(Debug)]
pub struct SRPServer {
    users: std::collections::HashMap<String, SRPUser>,
    sessions: std::collections::HashMap<Vec<u8>, SRPSession>,
    n: num_bigint::BigUint,
    g: num_bigint::BigUint,
    k: num_bigint::BigUint,
}

impl SRPServer {
    pub fn new(
        n: num_bigint::BigUint,
        g: num_bigint::BigUint,
        k: num_bigint::BigUint,
    ) -> SRPServer {
        SRPServer {
            users: std::collections::HashMap::new(),
            sessions: std::collections::HashMap::new(),
            n,
            g,
            k,
        }
    }

    pub fn register(
        &mut self,
        identity: &str,
        salt: &[u8],
        verifier: &num_bigint::BigUint,
    ) {
        self.users
            .insert(identity.to_string(), SRPUser::new(salt, verifier));
    }

    pub fn exchange_pubkeys(
        &mut self,
        user: &str,
        a_pub: &num_bigint::BigUint,
    ) -> (Vec<u8>, Vec<u8>, num_bigint::BigUint) {
        let userdata = self.users.get(user).unwrap();
        let b_priv = rand::thread_rng().gen_biguint_below(&self.n);
        let kv = self.k.clone() * userdata.verifier.clone();
        let b_pub = self.g.modpow(&b_priv, &self.n) + kv;

        let session = SRPSession {
            a_pub: a_pub.clone(),
            b_priv: b_priv,
            b_pub: b_pub.clone(),
            v: userdata.verifier.clone(),
            salt: userdata.salt.clone(),
        };
        let mut session_key = [0; 16];
        rand::thread_rng().fill(&mut session_key);
        let session_key = session_key.to_vec();
        self.sessions.insert(session_key.clone(), session);

        (session_key, userdata.salt.to_vec(), b_pub)
    }

    pub fn verify(&mut self, session: Vec<u8>, hmac: Vec<u8>) -> bool {
        let n = &self.n.clone();

        let session = self.sessions.get(&session).unwrap();

        let uinput =
            [session.a_pub.to_bytes_le(), session.b_pub.to_bytes_le()]
                .concat();
        let uh = crate::sha1::sha1(&uinput);
        let u = num_bigint::BigUint::from_bytes_le(&uh[..]);

        let s = (session.a_pub.clone() * session.v.modpow(&u, n))
            .modpow(&session.b_priv, n);
        let k = crate::sha1::sha1(&s.to_bytes_le());
        let server_hmac = crate::sha1::sha1_hmac(&k, &session.salt);

        hmac == server_hmac
    }
}

#[derive(Debug)]
pub struct SRPUser {
    salt: Vec<u8>,
    verifier: num_bigint::BigUint,
}

impl SRPUser {
    pub fn new(salt: &[u8], verifier: &num_bigint::BigUint) -> SRPUser {
        SRPUser {
            salt: salt.to_vec(),
            verifier: verifier.clone(),
        }
    }
}

#[derive(Debug)]
pub struct SRPSession {
    a_pub: num_bigint::BigUint,
    b_priv: num_bigint::BigUint,
    b_pub: num_bigint::BigUint,
    v: num_bigint::BigUint,
    salt: Vec<u8>,
}

#[derive(Debug)]
pub struct SRPClient<'a> {
    server: &'a mut SRPServer,
}

impl<'a> SRPClient<'a> {
    pub fn new(server: &'a mut SRPServer) -> SRPClient<'a> {
        SRPClient { server }
    }

    pub fn register(&mut self, user: &str, pass: &str) {
        let mut salt = [0; 16];
        rand::thread_rng().fill(&mut salt);
        let input = [&salt[..], pass.as_bytes()].concat();
        let xh = crate::sha1::sha1(&input);
        let x = num_bigint::BigUint::from_bytes_le(&xh[..]);
        let v = self.server.g.modpow(&x, &self.server.n);
        self.server.register(user, &salt, &v);
    }

    pub fn key_exchange(
        &mut self,
        user: &str,
        pass: &str,
    ) -> Option<num_bigint::BigUint> {
        let n = &self.server.n.clone();
        let g = &self.server.g.clone();
        let k = &self.server.k.clone();

        let a_priv = rand::thread_rng().gen_biguint_below(n);
        let a_pub = g.modpow(&a_priv, n);
        let (session, salt, b_pub) =
            self.server.exchange_pubkeys(user, &a_pub);

        let uinput = [a_pub.to_bytes_le(), b_pub.to_bytes_le()].concat();
        let uh = crate::sha1::sha1(&uinput);
        let u = num_bigint::BigUint::from_bytes_le(&uh[..]);

        let xinput = [salt.clone(), pass.as_bytes().to_vec()].concat();
        let xh = crate::sha1::sha1(&xinput);
        let x = num_bigint::BigUint::from_bytes_le(&xh[..]);

        let s = (b_pub - k * g.modpow(&x, n)).modpow(&(a_priv + u * x), n);
        let k = crate::sha1::sha1(&s.to_bytes_le());
        let hmac = crate::sha1::sha1_hmac(&k, &salt);

        if !self.server.verify(session, hmac.to_vec()) {
            return None
        }

        Some(s)
    }
}
