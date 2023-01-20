use std::fmt::Formatter;
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use anyhow::{Result, Ok, bail};

mod anisette_headers_provider;
mod adi_proxy;

#[cfg(not(target_env = "macos"))]
mod store_services_core;

#[cfg(target_env = "macos")]
mod aos_kit;

struct AnisetteHeaders;

#[derive(Debug)]
enum AnisetteMetaError {
    UnsupportedDevice
}

impl std::fmt::Display for AnisetteMetaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnisetteMetaError::{:?}", self)
    }
}

impl AnisetteHeaders {
    pub fn get_anisette_headers_provider() -> Result<Box<dyn AnisetteHeadersProvider>> {
        #[cfg(target_env = "macos")]
        return Ok(aos_kit::AOSKitHeadersProvider::new()?);

        bail!(AnisetteMetaError::UnsupportedDevice);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::AnisetteHeaders;

    #[test]
    fn fetch_anisette_auto() -> Result<()> {
        AnisetteHeaders::get_anisette_headers_provider()?.get_anisette_headers();
        Ok(())
    }
}
