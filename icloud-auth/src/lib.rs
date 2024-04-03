pub mod anisette;
mod client;
use std::fmt::Display;

pub use client::AppleAccount;
pub use omnisette::AnisetteConfiguration;

use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    Parse,
    AuthSrp,
    AuthSrpWithMessage(i64, String),
    ExtraStep(String),
    PlistError(#[from] plist::Error),
    ReqwestError(#[from] reqwest::Error),
    ErrorGettingAnisette(#[from] omnisette::AnisetteError)
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self))
    }
}
