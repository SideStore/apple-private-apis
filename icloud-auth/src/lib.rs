pub mod anisette;
pub mod request;

#[derive(Debug)]
pub enum Error {
    HttpRequest,
    Parse,
}
