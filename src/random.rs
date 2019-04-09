use rand::{Rng, RngCore, SeedableRng};

pub struct MersenneTwister {
    state: [u32; 624],
    index: u32,
}

pub struct MersenneTwisterSeed([u8; 2500]);

impl Default for MersenneTwisterSeed {
    fn default() -> MersenneTwisterSeed {
        MersenneTwisterSeed([0; 2500])
    }
}

impl AsMut<[u8]> for MersenneTwisterSeed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

fn mt_seed_to_state(seed: MersenneTwisterSeed) -> MersenneTwister {
    let mut state = [0; 624];
    for i in 0..624 {
        let idx = i * 4;
        state[i] = u32::from_ne_bytes([
            seed.0[idx],
            seed.0[idx + 1],
            seed.0[idx + 2],
            seed.0[idx + 3],
        ]);
    }
    let index = u32::from_ne_bytes([
        seed.0[2496],
        seed.0[2497],
        seed.0[2498],
        seed.0[2499],
    ]) % 624;
    MersenneTwister { state, index }
}

fn mt_state_to_seed(state: [u32; 624], index: u32) -> MersenneTwisterSeed {
    let mut seed = MersenneTwisterSeed([0; 2500]);
    let mut idx = 0;
    for i in &state[..] {
        let bytes = u32::to_ne_bytes(*i);
        seed.0[idx as usize] = bytes[0];
        seed.0[(idx + 1) as usize] = bytes[1];
        seed.0[(idx + 2) as usize] = bytes[2];
        seed.0[(idx + 3) as usize] = bytes[3];
        idx += 4;
    }
    let bytes = u32::to_ne_bytes(index);
    seed.0[2496] = bytes[0];
    seed.0[2497] = bytes[1];
    seed.0[2498] = bytes[2];
    seed.0[2499] = bytes[3];
    seed
}

impl MersenneTwister {
    fn new_unseeded() -> MersenneTwister {
        MersenneTwister {
            state: [0; 624],
            index: 0,
        }
    }

    pub fn from_u32(seed: u32) -> MersenneTwister {
        let mut state = [0; 624];
        state[0] = seed;
        for i in 1..624 {
            let prev = state[i - 1];
            state[i] = 1812433253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }

        MersenneTwister::from_seed(mt_state_to_seed(state, 0))
    }

    pub fn from_state(state: [u32; 624], index: u32) -> MersenneTwister {
        MersenneTwister::from_seed(mt_state_to_seed(state, index))
    }
}

impl RngCore for MersenneTwister {
    fn next_u32(&mut self) -> u32 {
        if self.index == 0 {
            for i in 0..624 {
                let y = (self.state[i] & 0x80000000)
                    .wrapping_add(self.state[(i + 1) % 624] & 0x7fffffff);
                self.state[i] = self.state[(i + 397) % 624] ^ (y >> 1);
                if (y % 2) != 0 {
                    self.state[i] = self.state[i] ^ 0x9908b0df;
                }
            }
        }

        let mut y = self.state[self.index as usize];
        y = y ^ (y >> 11);
        y = y ^ ((y << 7) & 0x9d2c5680);
        y = y ^ ((y << 15) & 0xefc60000);
        y = y ^ (y >> 18);

        self.index = (self.index + 1) % 624;

        return y;
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(rand_core::impls::fill_bytes_via_next(self, dest))
    }
}

impl SeedableRng for MersenneTwister {
    type Seed = MersenneTwisterSeed;

    fn from_seed(seed: MersenneTwisterSeed) -> MersenneTwister {
        let mut mt = MersenneTwister::new_unseeded();
        let MersenneTwister { state, index } = mt_seed_to_state(seed);
        for i in 0..624 {
            mt.state[i] = state[i];
        }
        mt.index = index;
        mt
    }
}

impl Clone for MersenneTwister {
    fn clone(&self) -> MersenneTwister {
        MersenneTwister {
            state: self.state,
            index: self.index,
        }
    }
}

impl std::fmt::Debug for MersenneTwister {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter,
    ) -> Result<(), std::fmt::Error> {
        write!(f, "MersenneTwister {{ ")?;
        std::fmt::Debug::fmt(&&self.state[..], f)?;
        write!(f, ", ")?;
        std::fmt::Debug::fmt(&self.index, f)?;
        write!(f, " }}")
    }
}

pub fn mt19937_stream_cipher(ciphertext: &[u8], key: u32) -> Vec<u8> {
    let mut mt = MersenneTwister::from_u32(key);
    let keystream: Vec<u8> = mt
        .sample_iter(&rand::distributions::Standard)
        .take(ciphertext.len())
        .collect();
    return crate::primitives::fixed_xor(ciphertext, &keystream[..]);
}

#[test]
fn test_mt19937_stream_cipher() {
    let key = rand::thread_rng().gen();
    let plaintext = b"Summertime and the wind is blowing outside in lower \
                     Chelsea and I don't know what I'm doing in the city, the \
                     sun is always in my eyes";
    let ciphertext = mt19937_stream_cipher(&plaintext[..], key);
    assert!(&plaintext[..] != &ciphertext[..]);
    let plaintext2 = mt19937_stream_cipher(&ciphertext[..], key);
    assert_eq!(&plaintext[..], &plaintext2[..]);
}
