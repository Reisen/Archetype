use http::uri::Uri;
use url::Url;

mod generators;

fn decode_secrets(secret: &[u8], item: &str) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Generate a key using the URI as the input.
    let url = item.parse::<Url>().unwrap();
    let key = {
        let mut key = Hmac::<Sha256>::new_varkey(secret).unwrap();
        key.input(url.host_str().unwrap().as_bytes());
        key
    };

    // Extract Bytes
    let res = key.result().code();
    let key = res.as_slice();

    #[rustfmt::skip]
    match url.scheme() {
        "gpg" => { generators::generate_gpg_key(url, key, true).ok(); }
        "key" => { generators::generate_key_material(url, key, true).ok(); }
        _ => {}
    };
}

/// Read in a single line, which is the input URI that describes the material to
/// be generated from the master key.
fn read_input() -> String {
    use std::io::BufRead;
    let mut line = String::new();
    let stdin = std::io::stdin();
    stdin.lock().read_line(&mut line).unwrap();
    line.trim().to_string()
}

// Generate Master Key
//
// Uses Argon2 in id mode, in order to generate a difficult to crack key for
// generating all our other key material. The resulting key is only as strong as
// the password.
fn generate_master_key(pass: &str, salt: &str) -> Vec<u8> {
    use argon2::{hash_raw, Config, ThreadMode, Variant, Version};

    // TODO: Come up with better configuration defaults.
    let config = &Config {
        ad:          &[],
        hash_length: 32,
        lanes:       1,
        mem_cost:    8,
        secret:      &[],
        thread_mode: ThreadMode::Parallel,
        time_cost:   1,
        variant:     Variant::Argon2id,
        version:     Version::Version13,
    };

    hash_raw(pass.as_bytes(), salt.as_bytes(), config).unwrap()
}

fn main() {
    // Parse Key Generation Arguments
    let args = std::env::args().collect::<Vec<String>>();
    let pass = args[1].clone();
    let salt = args[2].clone();
    println!("Pass: {}", pass);
    println!("Salt: {}", salt);

    assert!(salt.len() >= 8);
    assert!(pass.len() >= 8);

    // Read Input to Generate
    let inputs = read_input();
    let secret = generate_master_key(&*pass, &*salt);

    // Generate Key Material using Secret and URI
    decode_secrets(&*secret, &*inputs);
}
