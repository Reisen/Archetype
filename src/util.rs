use crate::error::Result;
use url::{Position, Url};

pub fn option(url: &Url, arg: &str) -> Result<String> {
    url.query_pairs()
        .find(|x| (*x).0 == arg)
        .map(|x| x.1)
        .ok_or_else(|| format!("Could not find argument: {}", arg).into())
        .map(|s| s.to_string())
}

// We're going to slice up until after path, this has the effect of acting as if
// there are ALWAYS arguments present, so URLs with no path will end up with a
// single slash at the end.
pub fn normalize_url_salt<'r>(uri: &'r Url) -> &'r str {
    &uri[.. Position::AfterPath]
}

#[cfg(test)]
mod testing {
    use super::*;

    #[test]
    fn test_expected_uri_salts() {
        use std::collections::HashMap;

        #[rustfmt::skip]
        let tests: HashMap<&str, &str> = [
            ("key:///etc/wireguard/wg0.conf", "key:///etc/wireguard/wg0.conf"),
            ("key:///etc/wireguard/wg0.conf?a=b", "key:///etc/wireguard/wg0.conf"),
            ("key:///etc/wireguard/config.d/?a=b", "key:///etc/wireguard/config.d/"),
            ("key://", "key:///"),
            ("password://username@google.com", "password://username@google.com/"),
            ("password://username@google.com?a=b", "password://username@google.com/"),
            ("password://username@google.com/?a=b", "password://username@google.com/"),
            ("password://username@google.com/foo?a=b", "password://username@google.com/foo"),
            ("password://username@google.com/foo/?a=b", "password://username@google.com/foo/"),
        ]
        .iter()
        .cloned()
        .collect();

        for (input, result) in tests.iter() {
            assert_eq!(normalize_url_salt(&input.parse().unwrap()), *result);
        }
    }
}
