use crate::crypto::SecretGenerator;
use std::error::Error;
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub struct GeneratedMaterial {
    pub output_key: Vec<u8>,
}

fn get_query(url: &Url, arg: &str) -> Result<String> {
    url.query_pairs()
        .find(|x| (*x).0 == arg)
        .map(|x| x.1)
        .ok_or(format!("Could not find argument: {}", arg).into())
        .map(|s| s.to_string())
}

// Generate Key material of some byte length N.
//
// URI Format Example:
// key:///file.txt?length=256
pub fn create_key(
    url: Url,
    mut gen: SecretGenerator,
) -> Result<GeneratedMaterial> {
    let length: usize = get_query(&url, "length")?.parse()?;
    let output_key = gen.get_bytes(length);
    println!("Out: {}", hex::encode(&output_key));
    Ok(GeneratedMaterial { output_key })
}
