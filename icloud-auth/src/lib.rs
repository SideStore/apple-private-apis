pub mod anisette;
mod client;
pub use client::AppleAccount;
#[derive(Debug)]
pub enum Error {
    HttpRequest,
    Parse,
    ErrorGettingAnisette,
    AuthSrp,
    AuthSrpWithMessage(i64, String),
    ExtraStep(String),
}
