use rand::{Rand, Rng, SeedableRng};
use std;

pub struct MersenneTwister {
    state: [u32; 624],
    index: usize,
}

impl MersenneTwister {
    fn new_unseeded () -> MersenneTwister {
        MersenneTwister { state: [0; 624], index: 0 }
    }
}

impl Rng for MersenneTwister {
    fn next_u32 (&mut self) -> u32 {
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

        let mut y = self.state[self.index];
        y = y ^ (y >> 11);
        y = y ^ ((y << 7) & 0x9d2c5680);
        y = y ^ ((y << 15) & 0xefc60000);
        y = y ^ (y >> 18);

        self.index = (self.index + 1) % 624;

        return y;
    }
}

impl SeedableRng<u32> for MersenneTwister {
    fn reseed (&mut self, seed: u32) {
        self.state[0] = seed;
        for i in 1..624 {
            let prev = self.state[i - 1];
            self.state[i] = 1812433253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }
    }

    fn from_seed (seed: u32) -> MersenneTwister {
        let mut mt = MersenneTwister::new_unseeded();
        mt.reseed(seed);
        mt
    }
}

impl SeedableRng<([u32; 624], usize)> for MersenneTwister {
    fn reseed (&mut self, seed: ([u32; 624], usize)) {
        let (state, index) = seed;
        for i in 0..624 {
            self.state[i] = state[i];
        }
        self.index = index;
    }

    fn from_seed (seed: ([u32; 624], usize)) -> MersenneTwister {
        let mut mt = MersenneTwister::new_unseeded();
        mt.reseed(seed);
        mt
    }
}

impl Rand for MersenneTwister {
    fn rand<R: Rng> (other: &mut R) -> MersenneTwister {
        MersenneTwister::from_seed(other.next_u32())
    }
}

impl Clone for MersenneTwister {
    fn clone (&self) -> MersenneTwister {
        MersenneTwister { state: self.state, index: self.index }
    }
}

impl std::fmt::Debug for MersenneTwister {
    fn fmt (&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        try!(write!(f, "MersenneTwister {{ "));
        try!(std::fmt::Debug::fmt(&&self.state[..], f));
        try!(write!(f, ", "));
        try!(std::fmt::Debug::fmt(&self.index, f));
        write!(f, " }}")
    }
}
