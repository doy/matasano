extern crate "rustc-serialize" as serialize;
extern crate openssl;

mod aes;
mod base64;
mod data;
mod primitives;
mod xor;

pub use aes::decrypt_aes_128_ecb;
pub use aes::find_aes_128_ecb_encrypted_string;
pub use base64::to_base64;
pub use primitives::fixed_xor;
pub use primitives::repeating_key_xor;
pub use xor::find_single_byte_xor_encrypted_string;
pub use xor::crack_single_byte_xor;
pub use xor::crack_repeating_key_xor;
