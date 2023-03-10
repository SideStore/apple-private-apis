use crate::adi_proxy::{ADIProxyAnisetteProvider, ConfigurableADIProxy};
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use anyhow::Result;
use std::fmt::Formatter;
use std::path::PathBuf;

mod adi_proxy;
mod anisette_headers_provider;

#[cfg(not(target_os = "macos"))]
mod store_services_core;

#[cfg(target_os = "macos")]
mod aos_kit;

#[cfg(feature = "remote-anisette")]
mod remote_anisette;

#[allow(dead_code)]
pub struct AnisetteHeaders;

#[derive(Debug)]
enum AnisetteMetaError {
    UnsupportedDevice,
}

impl std::fmt::Display for AnisetteMetaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnisetteMetaError::{:?}", self)
    }
}

pub const DEFAULT_ANISETTE_URL: &str = "https://ani.f1sh.me/";

pub struct AnisetteConfiguration {
    anisette_url: String,
    configuration_path: PathBuf,
}

impl AnisetteConfiguration {
    pub fn new() -> AnisetteConfiguration {
        AnisetteConfiguration {
            anisette_url: DEFAULT_ANISETTE_URL.to_string(),
            configuration_path: PathBuf::new(),
        }
    }

    pub fn anisette_url(&self) -> &String {
        &self.anisette_url
    }

    pub fn configuration_path(&self) -> &PathBuf {
        &self.configuration_path
    }

    pub fn set_anisette_url(mut self, anisette_url: String) -> AnisetteConfiguration {
        self.anisette_url = anisette_url;
        self
    }

    pub fn set_configuration_path(mut self, configuration_path: PathBuf) -> AnisetteConfiguration {
        self.configuration_path = configuration_path;
        self
    }
}

impl AnisetteHeaders {
    pub fn get_anisette_headers_provider(
        configuration: AnisetteConfiguration,
    ) -> Result<Box<dyn AnisetteHeadersProvider>> {
        #[cfg(target_os = "macos")]
        if let Ok(prov) = aos_kit::AOSKitAnisetteProvider::new() {
            return Ok(Box::new(prov));
        }

        #[cfg(not(target_os = "macos"))]
        {
            if let Ok(mut ssc_adi_proxy) = store_services_core::StoreServicesCoreADIProxy::new(
                configuration.configuration_path(),
            ) {
                let _ = ssc_adi_proxy
                    .set_provisioning_path(configuration.configuration_path().to_str().unwrap());
                return Ok(Box::new(ADIProxyAnisetteProvider::new(ssc_adi_proxy)?));
            }
        }

        #[cfg(feature = "remote-anisette")]
        return Ok(Box::new(remote_anisette::RemoteAnisetteProvider::new(
            configuration.anisette_url,
        )));

        #[cfg(not(feature = "remote-anisette"))]
        bail!(AnisetteMetaError::UnsupportedDevice)
    }
}

#[cfg(test)]
mod tests {
    use crate::{AnisetteConfiguration, AnisetteHeaders};
    use anyhow::Result;
    use std::path::PathBuf;

    #[test]
    fn fetch_anisette_auto() -> Result<()> {
        let mut provider = AnisetteHeaders::get_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        println!("Headers: {:?}", provider.get_authentication_headers()?);
        Ok(())
    }
}
