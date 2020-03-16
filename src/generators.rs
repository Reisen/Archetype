mod electrum;
mod gpg;
mod key;

pub use electrum::create_seed;
pub use gpg::create_gpg_key;
pub use key::create_key;
