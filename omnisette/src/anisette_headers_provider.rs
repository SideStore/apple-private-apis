use std::collections::HashMap;

pub trait AnisetteHeadersProvider {
    fn get_anisette_headers(&self) -> HashMap<String, String>;
}

impl dyn AnisetteHeadersProvider {
    // Normalizes headers to ensure that all the required headers are given.
    fn get_authentication_headers(&self) -> HashMap<String, String> {
        self.get_anisette_headers()
    }
}
