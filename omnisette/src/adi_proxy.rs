use std::collections::HashMap;
use anyhow::Result;
use crate::anisette_headers_provider::AnisetteHeadersProvider;

#[derive(Debug)]
pub enum ADIError {
    Unknown(i32)
}

impl ADIError {
    pub fn resolve(error_number: i32) -> ADIError {
        ADIError::Unknown(error_number)
    }
}

pub struct SynchronizeData {
    pub mid: Vec<u8>,
    pub srm: Vec<u8>
}

pub struct StartProvisioningData {
    pub cpim: Vec<u8>
}

pub struct RequestOTPData {
    pub otp: Vec<u8>,
    pub mid: Vec<u8>
}

pub trait ADIProxy {
    fn erase_provisioning(&mut self, ds_id: u64) -> Result<(), ADIError>;
    fn synchronize(&mut self, ds_id: u64, sim: &[u8]) -> Result<SynchronizeData, ADIError>;
    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError>;
    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError>;
    fn start_provisioning(&mut self, ds_id: u64, spim: &[u8]) -> Result<StartProvisioningData, ADIError>;
    fn is_machine_provisioned(&self, ds_id: u64) -> bool;
    fn request_otp(&self, ds_id: u64) -> Result<RequestOTPData, ADIError>;

    fn get_client_info_header(&self) -> String;
    fn get_local_user_uuid(&self) -> String;
    fn get_device_identifier(&self) -> String;
    fn get_serial_number(&self) -> String;
}

pub trait ConfigurableADIProxy: ADIProxy {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError>;
    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError>;
}

impl dyn ADIProxy {
    fn provision_device(&self) {
        todo!();
    }
}

pub struct ADIProxyAnisetteProvider<ProxyType: ADIProxy> {
    adi_proxy: ProxyType
}

impl<ProxyType: ADIProxy> ADIProxyAnisetteProvider<ProxyType> {
    pub fn new(adi_proxy: ProxyType) -> ADIProxyAnisetteProvider<ProxyType> {
        ADIProxyAnisetteProvider {
            adi_proxy
        }
    }
}

impl<ProxyType: ADIProxy> AnisetteHeadersProvider for ADIProxyAnisetteProvider<ProxyType> {
    fn get_anisette_headers(&self) -> HashMap<String, String> {
        todo!()
    }
}
