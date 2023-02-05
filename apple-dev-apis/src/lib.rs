mod session;
pub use session::XcodeSession;

#[derive(Debug)]
pub enum Error {
    AuthError(i64, String),
    GenericError,
}
