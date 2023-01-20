use std::fmt::Formatter;
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use crate::adi_proxy::{ADIProxyAnisetteProvider};
use anyhow::{Result, bail};
use crate::remote_anisette::RemoteAnisetteProvider;

mod anisette_headers_provider;
mod adi_proxy;

#[cfg(not(target_env = "macos"))]
mod store_services_core;

#[cfg(target_env = "macos")]
mod aos_kit;

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

pub const FALLBACK_ANISETTE_URL: &str = "https://ani.f1sh.me/";

impl AnisetteHeaders {
    pub fn get_anisette_headers_provider() -> Box<dyn AnisetteHeadersProvider> {
        Self::get_anisette_headers_provider_with_fallback_url(FALLBACK_ANISETTE_URL)
    }

    pub fn get_anisette_headers_provider_with_fallback_url(fallback_url: &str) -> Box<dyn AnisetteHeadersProvider> {
        #[cfg(target_env = "macos")]
        match aos_kit::AOSKitAnisetteProvider::new() {
            Ok(prov) => return Box::new(prov),
            Err(_) => {}
        }

        #[cfg(not(target_env = "macos"))]
        {
            match store_services_core::StoreServicesCoreADIProxy::new("adi_data/") {
                Ok(ssc_adi_proxy) =>
                    return Box::new(ADIProxyAnisetteProvider::new(ssc_adi_proxy)),
                Err(_) => {}
            }
        }

        Box::new(RemoteAnisetteProvider::new(fallback_url))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::AnisetteHeaders;

    #[test]
    fn fetch_anisette_auto() -> Result<()> {
        AnisetteHeaders::get_anisette_headers_provider().get_anisette_headers();
        Ok(())
    }
}
