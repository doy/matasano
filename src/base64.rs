use serialize::base64::{ToBase64, STANDARD};

pub fn to_base64 (bytes: &[u8]) -> String {
    return bytes.to_base64(STANDARD);
}
