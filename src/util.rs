use crate::error::Result;
use url::Url;

pub fn option(url: &Url, arg: &str) -> Result<String> {
    url.query_pairs()
        .find(|x| (*x).0 == arg)
        .map(|x| x.1)
        .ok_or_else(|| format!("Could not find argument: {}", arg).into())
        .map(|s| s.to_string())
}
