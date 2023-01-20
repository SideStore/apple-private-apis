use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;
use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, Utc};
use machineid_rs::{Encryption, HWIDComponent, IdBuilder};
use reqwest::blocking::{Client, ClientBuilder, RequestBuilder};
use reqwest::header::{HeaderMap, HeaderValue};
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

trait ToPlist {
    fn plist(self) -> Result<plist::Dictionary>;
}

impl ToPlist for reqwest::blocking::Response {
    fn plist(self) -> Result<plist::Dictionary> {
        Ok(plist::Value::from_reader_xml(&*self.bytes()?)?.as_dictionary().unwrap().to_owned())
    }
}

impl Display for ADIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for ADIError {}

pub struct SynchronizeData {
    pub mid: Vec<u8>,
    pub srm: Vec<u8>
}

pub struct StartProvisioningData {
    pub cpim: Vec<u8>,
    pub session: u32
}

pub struct RequestOTPData {
    pub otp: Vec<u8>,
    pub mid: Vec<u8>
}

pub trait ADIProxy {
    fn erase_provisioning(&mut self, ds_id: i64) -> Result<(), ADIError>;
    fn synchronize(&mut self, ds_id: i64, sim: &[u8]) -> Result<SynchronizeData, ADIError>;
    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError>;
    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError>;
    fn start_provisioning(&mut self, ds_id: i64, spim: &[u8]) -> Result<StartProvisioningData, ADIError>;
    fn is_machine_provisioned(&self, ds_id: i64) -> bool;
    fn request_otp(&self, ds_id: i64) -> Result<RequestOTPData, ADIError>;

    fn set_local_user_uuid(&mut self, local_user_uuid: String);
    fn set_device_identifier(&mut self, device_identifier: String);

    fn get_local_user_uuid(&self) -> String;
    fn get_device_identifier(&self) -> String;
    fn get_serial_number(&self) -> String;
}

pub trait ConfigurableADIProxy: ADIProxy {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError>;
    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError>;
}

const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
const CLIENT_INFO_HEADER: &str = "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";

const DS_ID: i64 = -2;

impl dyn ADIProxy {
    fn make_http_client(&self) -> Result<Client> {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_str("text/x-xml-plist")?);

        headers.insert("X-Mme-Client-Info", HeaderValue::from_str(CLIENT_INFO_HEADER)?);
        headers.insert("X-Mme-Device-Id", HeaderValue::from_str(self.get_device_identifier().as_str())?);
        headers.insert("X-Apple-I-MD-LU", HeaderValue::from_str(self.get_local_user_uuid().as_str())?);
        headers.insert("X-Apple-I-SRL-NO", HeaderValue::from_str(self.get_serial_number().as_str())?);

        println!("headers: {:?}", headers);

        let http_client = ClientBuilder::new()
            .http1_title_case_headers()
            .danger_accept_invalid_certs(true)
            .connection_verbose(true)
            .user_agent(AKD_USER_AGENT)
            .default_headers(headers) // TODO: pin the apple certificate
            .build()?;

        Ok(http_client)
    }

    pub fn provision_device(&mut self) -> Result<()> {
        let client = self.make_http_client()?;
        let base64_engine = base64::engine::general_purpose::STANDARD;

        let url_bag_res = client.get("https://gsa.apple.com/grandslam/GsService2/lookup")
            .send()?
            .plist()?;

        let urls = url_bag_res.get("urls").unwrap().as_dictionary().unwrap();

        let start_provisioning_url = urls.get("midStartProvisioning").unwrap().as_string().unwrap();
        let finish_provisioning_url = urls.get("midFinishProvisioning").unwrap().as_string().unwrap();

        // Create a basically empty plist, containing the keys "Header" and "Request"
        let mut body = plist::Dictionary::new();
        body.insert("Header".to_string(), plist::Value::Dictionary(plist::Dictionary::new()));
        body.insert("Request".to_string(), plist::Value::Dictionary(plist::Dictionary::new()));

        let mut sp_request = Vec::new();
        plist::Value::Dictionary(body).to_writer_xml(&mut sp_request)?;

       let response = client
           .post(start_provisioning_url)
           .body(sp_request)
           .send()?
           .plist()?;

       let response = response.get("Response").unwrap().as_dictionary().unwrap();

       let spim = response
           .get("spim")
           .unwrap()
           .as_string()
           .unwrap()
           .to_owned();

        let spim = base64_engine.decode(spim)?;
        let first_step = self.start_provisioning(DS_ID, spim.as_slice())?;

        let mut body = plist::Dictionary::new();
        let mut request = plist::Dictionary::new();
        request.insert("cpim".to_owned(), plist::Value::String(base64_engine.encode(first_step.cpim)));
        body.insert("Header".to_owned(), plist::Value::Dictionary(plist::Dictionary::new()));
        body.insert("Request".to_owned(), plist::Value::Dictionary(request));

        let mut fp_request = Vec::new();
        plist::Value::Dictionary(body).to_writer_xml(&mut fp_request)?;

        let response = client
            .post(finish_provisioning_url)
            .body(fp_request)
            .send()?
            .plist()?;

        let response = response.get("Response").unwrap().as_dictionary().unwrap();

        let ptm = base64_engine.decode(response.get("ptm").unwrap().as_string().unwrap().to_owned())?;
        let tk = base64_engine.decode(response.get("tk").unwrap().as_string().unwrap().to_owned())?;

        self.end_provisioning(first_step.session, ptm.as_slice(), tk.as_slice())?;

        Ok(())
    }
}

pub struct ADIProxyAnisetteProvider<ProxyType: ADIProxy + 'static> {
    adi_proxy: ProxyType
}

// arbitrary key
const ADI_KEY: &str = "The most secure key is this one. Not only because it is open-source, but also because I said it, and that it is real. C'est réel en fait. ";

impl<ProxyType: ADIProxy + 'static> ADIProxyAnisetteProvider<ProxyType> {
    pub fn new(mut adi_proxy: ProxyType) -> Result<ADIProxyAnisetteProvider<ProxyType>> {
        let mut device_identifier_builder = IdBuilder::new(Encryption::SHA1);
        let mut local_uuid_builder = IdBuilder::new(Encryption::SHA256);

        adi_proxy.set_device_identifier(device_identifier_builder
            .add_component(HWIDComponent::MachineName)
            .add_component(HWIDComponent::MacAddress)
            .add_component(HWIDComponent::SystemID).build(ADI_KEY)?);
        adi_proxy.set_device_identifier(local_uuid_builder
            .add_component(HWIDComponent::MachineName)
            .add_component(HWIDComponent::MacAddress)
            .add_component(HWIDComponent::SystemID).build(ADI_KEY)?);

        Ok(ADIProxyAnisetteProvider {
            adi_proxy
        })
    }
}

impl<ProxyType: ADIProxy + 'static> AnisetteHeadersProvider for ADIProxyAnisetteProvider<ProxyType> {
    fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>> {
        let adi_proxy = &mut self.adi_proxy as &mut dyn ADIProxy;

        if !adi_proxy.is_machine_provisioned(DS_ID) {
            adi_proxy.provision_device()?;
        }

        let base64_engine = base64::engine::general_purpose::STANDARD;

        let machine_data = adi_proxy.request_otp(DS_ID)?;

        let mut headers = HashMap::new();
        headers.insert("X-Apple-I-MD".to_string(), base64_engine.encode(machine_data.otp));
        headers.insert("X-Apple-I-MD-M".to_string(), base64_engine.encode(machine_data.mid));
        headers.insert("X-Apple-I-MD-RINFO".to_string(), "17106176".to_string());
        headers.insert("X-Apple-I-MD-LU".to_string(), adi_proxy.get_local_user_uuid());
        headers.insert("X-Apple-I-SRL-NO".to_string(), adi_proxy.get_serial_number());
        headers.insert("X-Mme-Client-Info".to_string(), CLIENT_INFO_HEADER.to_string());
        headers.insert("X-Mme-Device-Id".to_string(), adi_proxy.get_device_identifier());

        Ok(headers)
    }
}
