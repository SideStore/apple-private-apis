use anyhow::Result;
use std::fmt::Formatter;
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use crate::adi_proxy::{ADIProxyAnisetteProvider};

mod anisette_headers_provider;
mod adi_proxy;

#[cfg(not(target_env = "macos"))]
mod store_services_core;

#[cfg(target_env = "macos")]
mod aos_kit;

#[cfg(feature = "remote-anisette")]
mod remote_anisette;

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

pub const DEFAULT_ANISETTE_URL: &str = "https://ani.f1sh.me/";

impl AnisetteHeaders {
    pub fn get_anisette_headers_provider() -> Result<Box<dyn AnisetteHeadersProvider>> {
        Self::get_anisette_headers_provider_with_fallback_url(DEFAULT_ANISETTE_URL)
    }

    pub fn get_anisette_headers_provider_with_fallback_url(fallback_url: &str) -> Result<Box<dyn AnisetteHeadersProvider>> {
        #[cfg(target_env = "macos")]
        match aos_kit::AOSKitAnisetteProvider::new() {
            Ok(prov) => return Ok(Box::new(prov)),
            Err(_) => {}
        }

        #[cfg(not(target_env = "macos"))]
        {
            match store_services_core::StoreServicesCoreADIProxy::new("adi_data/") {
                Ok(ssc_adi_proxy) =>
                    return Ok(Box::new(ADIProxyAnisetteProvider::new(ssc_adi_proxy)?)),
                Err(_) => {}
            }
        }

        #[cfg(feature = "remote-anisette")]
        return Ok(Box::new(remote_anisette::RemoteAnisetteProvider::new(fallback_url)));

        #[cfg(not(feature = "remote-anisette"))]
        bail!(AnisetteMetaError::UnsupportedDevice)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::any::type_name;
    use crate::AnisetteHeaders;

    #[test]
    fn fetch_anisette_auto() -> Result<()> {
        let mut provider = AnisetteHeaders::get_anisette_headers_provider()?;
        println!("Headers: {:?}", provider.get_authentication_headers()?);
        Ok(())
    }
}
