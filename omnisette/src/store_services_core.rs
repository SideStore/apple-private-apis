use anyhow::Result;
use crate::adi_proxy::{ADIError, ADIProxy, ConfigurableADIProxy, RequestOTPData, StartProvisioningData, SynchronizeData};

pub struct StoreServicesCoreADIProxy {

}

impl StoreServicesCoreADIProxy {
    pub fn new(library_path: &str) -> Result<StoreServicesCoreADIProxy> {
        // Ok(StoreServicesCoreADIProxy {
//
        // })
        todo!()
    }
}

impl ADIProxy for StoreServicesCoreADIProxy {
    fn erase_provisioning(&mut self, ds_id: u64) -> Result<(), ADIError> {
        todo!()
    }

    fn synchronize(&mut self, ds_id: u64, sim: &[u8]) -> Result<SynchronizeData, ADIError> {
        todo!()
    }

    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError> {
        todo!()
    }

    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError> {
        todo!()
    }

    fn start_provisioning(&mut self, ds_id: u64, spim: &[u8]) -> Result<StartProvisioningData, ADIError> {
        todo!()
    }

    fn is_machine_provisioned(&self, ds_id: u64) -> bool {
        todo!()
    }

    fn request_otp(&self, ds_id: u64) -> Result<RequestOTPData, ADIError> {
        todo!()
    }

    fn get_client_info_header(&self) -> String {
        todo!()
    }

    fn get_local_user_uuid(&self) -> String {
        todo!()
    }

    fn get_device_identifier(&self) -> String {
        todo!()
    }

    fn get_serial_number(&self) -> String {
        todo!()
    }
}

impl ConfigurableADIProxy for StoreServicesCoreADIProxy {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError> {
        todo!()
    }

    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::adi_proxy::ADIProxyAnisetteProvider;
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::store_services_core::StoreServicesCoreADIProxy;

    #[test]
    fn fetch_anisette_ssc() -> Result<()> {
        ADIProxyAnisetteProvider::new(StoreServicesCoreADIProxy::new("lib/")?)
            .get_anisette_headers();
        Ok(())
    }
}
