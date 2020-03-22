use url::Url;

mod crypto;
mod error;
mod generators;
mod util;

fn decode_secrets(secret: &[u8], item: &str) {
    // Enforce Parsing of a URL, and create a secret generator.
    let uri = item.parse::<Url>().unwrap();
    let salt = &uri[.. if uri.path() == "/" {
        url::Position::AfterHost
    } else {
        url::Position::AfterPath
    }];
    let secret_generator = crypto::Entropy::new(secret, salt);
    eprintln!("Salt:  {}", salt);

    #[rustfmt::skip]
    match uri.scheme() {
        "gpg"       => { generators::gpg_key(uri, secret_generator, true).ok(); }
        "key"       => { generators::key(uri, secret_generator).ok(); }
        "electrum"  => { generators::seed(uri, secret_generator).ok(); }
        "wireguard" => { generators::wireguard(uri, secret_generator).ok(); }
        _ =>           { eprintln!("Error: Unknown URI"); }
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

    hash_raw(pass.as_bytes(), salt.as_bytes(), config).unwrap()
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
    let pass = read_input();
    let salt = args[1].clone();
    let line = args[2].clone();
    eprintln!("Salt:  {}", salt);
    eprintln!("URI:   {}", line);

    assert!(pass.len() >= 8);
    assert!(salt.len() >= 8);

    // Read Input to Generate
    let secret = generate_master_key(&*pass, &*salt);

    // Display Key Emoji
    render_master_emoji(&secret[0 .. 3]);

    // Generate Key Material using Secret and URI
    decode_secrets(&*secret, &*line);
}
