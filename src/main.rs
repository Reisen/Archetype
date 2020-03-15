use url::Url;

mod crypto;
mod generators;

fn decode_secrets(secret: &[u8], item: &str) {
    // Enforce Parsing of a URL, and create a secret generator.
    let uri = item.parse::<Url>().unwrap();
    let salt = item.as_bytes();
    let secret_generator = crypto::SecretGenerator::new(secret, salt);

    #[rustfmt::skip]
    match uri.scheme() {
        "gpg" => { generators::create_gpg_key(uri, secret_generator, true).ok(); }
        "key" => { generators::create_key(uri, secret_generator).ok(); }
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
        hash_length: 64, // Bytes
        lanes:       8,
        mem_cost:    1_048_576, // KiB
        secret:      &[],
        thread_mode: ThreadMode::Parallel,
        time_cost:   8,
        variant:     Variant::Argon2id,
        version:     Version::Version13,
    };

    let hash = hash_raw(pass.as_bytes(), salt.as_bytes(), config).unwrap();
    render_master_emoji(&hash[0 .. 8]);
    hash
}

fn render_master_emoji(bytes: &[u8]) {
    #[rustfmt::skip]
    let emoji = &[
        "👻","🤖","👺","🐲",
        "🍀","🐨","🐸","🦁",
        "🍄","🌺","🍩","🌽",
        "🥝","🏀","🚀","💎",
    ];

    eprint!("Emoji: ");
    for byte in bytes {
        eprint!("{}", emoji[(byte & 0xF) as usize]);
        eprint!("{} ", emoji[((byte >> 4) & 0xF) as usize]);
    }
    eprintln!("");
}

fn main() {
    // Parse Key Generation Arguments
    let args = std::env::args().collect::<Vec<String>>();
    let pass = args[1].clone();
    let salt = args[2].clone();
    eprintln!("Pass:  {}", pass);
    eprintln!("Salt:  {}", salt);

    assert!(salt.len() >= 8);
    assert!(pass.len() >= 8);

    // Read Input to Generate
    let inputs = read_input();
    let secret = generate_master_key(&*pass, &*salt);

    // Display Key Emoji
    render_master_emoji(&secret[0 .. 3]);

    // Generate Key Material using Secret and URI
    decode_secrets(&*secret, &*inputs);
}
