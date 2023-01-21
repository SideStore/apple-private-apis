pub mod anisette;
mod client;
pub use client::AppleAccount;
#[derive(Debug)]
pub enum Error {
    HttpRequest,
    Parse,
    AuthSrp,
    AuthSrpWithMessage(i64, String),
}
