use crate::crypto::Entropy;
use crate::error::Result;
use crate::util;
use url::Url;

pub struct Key(Vec<u8>);

pub fn key(url: Url, mut source: Entropy) -> Result<Key> {
    let length: usize = util::option(&url, "length")?.parse()?;
    let output = source.get_bytes(length);
    println!("Key:   {}", hex::encode(&output));
    Ok(Key(output))
}
