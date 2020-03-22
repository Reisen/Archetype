use crate::crypto::Entropy;
use crate::error::Result;
use url::Url;

pub struct Wireguard(Vec<u8>);

pub fn wireguard(_: Url, mut source: Entropy) -> Result<Wireguard> {
    let mut output = source.get_bytes(32);
    println!("Key:   {}", base64::encode(&output));
    output[0] &= 248;
    output[31] &= 63;
    output[31] |= 64;
    println!("Key:   {}", base64::encode(&output));
    Ok(Wireguard(output))
}
