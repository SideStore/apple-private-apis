use crate::adi_proxy::ProvisioningError::InvalidResponse;
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_engine;
use log::trace;
use plist::{Dictionary, Value};
use rand::RngCore;
#[cfg(feature = "async")]
use reqwest::{Client, ClientBuilder, Response};
#[cfg(not(feature = "async"))]
use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub struct ServerError {
    pub code: i64,
    pub description: String
}

#[derive(Debug)]
pub enum ProvisioningError {
    InvalidResponse,
    ServerError(ServerError)
}

impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProvisioningError {}

#[derive(Debug)]
pub enum ADIError {
    Unknown(i32),
    ProvisioningError(ProvisioningError)
}

impl ADIError {
    pub fn resolve(error_number: i32) -> ADIError {
        ADIError::Unknown(error_number)
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait)]
trait ToPlist {
    #[cfg(feature = "async")]
    async fn plist(self) -> Result<Dictionary>;
    #[cfg(not(feature = "async"))]
    fn plist(self) -> Result<Dictionary>;
}

#[cfg_attr(feature = "async", async_trait::async_trait)]
impl ToPlist for Response {
    #[cfg(feature = "async")]
    async fn plist(self) -> Result<Dictionary> {
        if let Ok(property_list) = Value::from_reader_xml(&*self.bytes().await?) {
            Ok(property_list
                .as_dictionary()
                .unwrap()
                .to_owned())
        } else {
            Err(ProvisioningError::InvalidResponse.into())
        }
    }
    #[cfg(not(feature = "async"))]
    fn plist(self) -> Result<Dictionary> {
        if let Ok(property_list) = Value::from_reader_xml(&*self.bytes()?) {
            Ok(property_list
                .as_dictionary()
                .unwrap()
                .to_owned())
        } else {
            Err(ProvisioningError::InvalidResponse.into())
        }
    }
}

impl Display for ADIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ADIError {}

pub struct SynchronizeData {
    pub mid: Vec<u8>,
    pub srm: Vec<u8>,
}

pub struct StartProvisioningData {
    pub cpim: Vec<u8>,
    pub session: u32,
}

pub struct RequestOTPData {
    pub otp: Vec<u8>,
    pub mid: Vec<u8>,
}

// ADIProxy helper macros to reduce duplicate code between async and sync
// we unfortunately can't use a helper struct + impl because of issues passing a dyn ADIProxy to the methods

macro_rules! ADIProxy_make_http_client {
    ($adi_proxy: expr) => {
        {
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", HeaderValue::from_str("text/x-xml-plist")?);

            headers.insert(
                "X-Mme-Client-Info",
                HeaderValue::from_str(CLIENT_INFO_HEADER)?,
            );
            headers.insert(
                "X-Mme-Device-Id",
                HeaderValue::from_str($adi_proxy.get_device_identifier().as_str())?,
            );
            headers.insert(
                "X-Apple-I-MD-LU",
                HeaderValue::from_str($adi_proxy.get_local_user_uuid().as_str())?,
            );
            headers.insert(
                "X-Apple-I-SRL-NO",
                HeaderValue::from_str($adi_proxy.get_serial_number().as_str())?,
            );

            trace!("Headers sent: {headers:?}");

            let http_client = ClientBuilder::new()
                .http1_title_case_headers()
                .danger_accept_invalid_certs(true) // TODO: pin the apple certificate
                .user_agent(AKD_USER_AGENT)
                .default_headers(headers)
                .build()?;

            anyhow::Ok::<Client>(http_client)
        }
    };
}

macro_rules! ADIProxy_get_urls_and_create_sp_request {
    ($urls: expr) => {
        {
            let start_provisioning_url = $urls
                .get("midStartProvisioning")
                .unwrap()
                .as_string()
                .unwrap();
            let finish_provisioning_url = $urls
                .get("midFinishProvisioning")
                .unwrap()
                .as_string()
                .unwrap();

            let mut body = Dictionary::new();
            body.insert("Header".to_string(), Value::Dictionary(Dictionary::new()));
            body.insert("Request".to_string(), Value::Dictionary(Dictionary::new()));

            let mut sp_request = Vec::new();
            Value::Dictionary(body).to_writer_xml(&mut sp_request)?;

            anyhow::Ok::<(&str, &str, Vec<u8>)>((start_provisioning_url, finish_provisioning_url, sp_request))
        }
    };
}

macro_rules! ADIProxy_create_fp_request {
    ($adi_proxy: expr, $response: expr) => {
        {
            let spim = $response
                .get("spim")
                .unwrap()
                .as_string()
                .unwrap()
                .to_owned();

            let spim = base64_engine.decode(spim)?;
            let first_step = $adi_proxy.start_provisioning(DS_ID, spim.as_slice())?;

            let mut body = Dictionary::new();
            let mut request = Dictionary::new();
            request.insert(
                "cpim".to_owned(),
                Value::String(base64_engine.encode(first_step.cpim.clone())),
            );
            body.insert("Header".to_owned(), Value::Dictionary(Dictionary::new()));
            body.insert("Request".to_owned(), Value::Dictionary(request));

            let mut fp_request = Vec::new();
            Value::Dictionary(body).to_writer_xml(&mut fp_request)?;

            anyhow::Ok::<(Vec<u8>, StartProvisioningData)>((fp_request, first_step))
        }
    };
}

macro_rules! ADIProxy_decode_and_end_provisioning {
    ($adi_proxy: expr, $response: expr, $first_step: expr) => {
        {
            let ptm = base64_engine.decode($response.get("ptm").unwrap().as_string().unwrap())?;
            let tk = base64_engine.decode($response.get("tk").unwrap().as_string().unwrap())?;

            $adi_proxy.end_provisioning($first_step.session, ptm.as_slice(), tk.as_slice())?;

            anyhow::Ok(())
        }
    };
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
pub trait ADIProxy {
    #[cfg(feature = "async")]
    async fn provision_device(&mut self) -> Result<()> {
        let client = ADIProxy_make_http_client!(self)?;

        let url_bag_res = client
            .get("https://gsa.apple.com/grandslam/GsService2/lookup")
            .send()
            .await?
            .plist()
            .await?;

        let (start_provisioning_url, finish_provisioning_url, sp_request) = ADIProxy_get_urls_and_create_sp_request!(url_bag_res.get("urls").unwrap().as_dictionary().unwrap())?;

        trace!("First provisioning request...");
        let response = client
            .post(start_provisioning_url)
            .body(sp_request)
            .send()
            .await?
            .plist()
            .await?;

        let (fp_request, first_step) = ADIProxy_create_fp_request!(self, response.get_response()?)?;

        trace!("Second provisioning request...");
        let response = client
            .post(finish_provisioning_url)
            .body(fp_request)
            .send()
            .await?
            .plist()
            .await?;

        ADIProxy_decode_and_end_provisioning!(self, response.get_response()?, first_step)?;

        Ok(())
    }
    #[cfg(not(feature = "async"))]
    fn provision_device(&mut self) -> Result<()> {
        let client = ADIProxy_make_http_client!(self)?;

        let url_bag_res = client
            .get("https://gsa.apple.com/grandslam/GsService2/lookup")
            .send()?
            .plist()?;

        let (start_provisioning_url, finish_provisioning_url, sp_request) = ADIProxy_get_urls_and_create_sp_request!(url_bag_res.get("urls").unwrap().as_dictionary().unwrap())?;

        trace!("First provisioning request...");
        let response = client
            .post(start_provisioning_url)
            .body(sp_request)
            .send()?
            .plist()?;

        let (fp_request, first_step) = ADIProxy_create_fp_request!(self, response.get_response()?)?;

        trace!("Second provisioning request...");
        let response = client
            .post(finish_provisioning_url)
            .body(fp_request)
            .send()?
            .plist()?;

        ADIProxy_decode_and_end_provisioning!(self, response.get_response()?, first_step)?;

        Ok(())
    }

    fn erase_provisioning(&mut self, ds_id: i64) -> Result<(), ADIError>;
    fn synchronize(&mut self, ds_id: i64, sim: &[u8]) -> Result<SynchronizeData, ADIError>;
    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError>;
    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError>;
    fn start_provisioning(
        &mut self,
        ds_id: i64,
        spim: &[u8],
    ) -> Result<StartProvisioningData, ADIError>;
    fn is_machine_provisioned(&self, ds_id: i64) -> bool;
    fn request_otp(&self, ds_id: i64) -> Result<RequestOTPData, ADIError>;

    fn set_local_user_uuid(&mut self, local_user_uuid: String);
    fn set_device_identifier(&mut self, device_identifier: String) -> Result<()>;

    fn get_local_user_uuid(&self) -> String;
    fn get_device_identifier(&self) -> String;
    fn get_serial_number(&self) -> String;
}

pub trait ConfigurableADIProxy: ADIProxy {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError>;
    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError>;
}

const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
const CLIENT_INFO_HEADER: &str =
    "<MacBookPro17,1> <macOS;12.2.1;21D62> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";
const DS_ID: i64 = -2;
pub const IDENTIFIER_LENGTH: usize = 16;

trait AppleRequestResult {
    fn check_status(&self) -> Result<()>;
    fn get_response(&self) -> Result<&Dictionary>;
}

impl AppleRequestResult for Dictionary {
    fn check_status(&self) -> Result<()> {
        let status = self.get("Status").ok_or(InvalidResponse)?.as_dictionary().unwrap();
        let code = status.get("ec").unwrap().as_signed_integer().unwrap();
        if code != 0 {
            let description = status.get("em").unwrap().as_string().unwrap().to_string();
            Err(ProvisioningError::ServerError(ServerError {
                code,
                description
            }).into())
        } else {
            Ok(())
        }
    }

    fn get_response(&self) -> Result<&Dictionary> {
        if let Some(response) = self.get("Response") {
            let response = response.as_dictionary().unwrap();
            response.check_status()?;
            Ok(response)
        } else {
            Err(InvalidResponse.into())
        }
    }
}

pub struct ADIProxyAnisetteProvider<ProxyType: ADIProxy + 'static> {
    adi_proxy: ProxyType,
}

impl<ProxyType: ADIProxy + 'static> ADIProxyAnisetteProvider<ProxyType> {
    pub fn new(mut adi_proxy: ProxyType, configuration_path: PathBuf) -> Result<ADIProxyAnisetteProvider<ProxyType>> {
        let identifier_file_path = configuration_path.join("identifier");
        let mut identifier_file = std::fs::OpenOptions::new().create(true).read(true).write(true).open(identifier_file_path)?;
        let mut identifier = [0u8; IDENTIFIER_LENGTH];
        if identifier_file.metadata()?.len() == IDENTIFIER_LENGTH as u64 {
            identifier_file.read_exact(&mut identifier)?;
        } else {
            rand::thread_rng().fill_bytes(&mut identifier);
            identifier_file.write_all(&identifier)?;
        }

        let mut local_user_uuid_hasher = Sha256::new();
        local_user_uuid_hasher.update(identifier);

        adi_proxy.set_device_identifier(uuid::Uuid::from_bytes(identifier).to_string().to_uppercase())?; // UUID, uppercase
        adi_proxy.set_local_user_uuid(hex::encode(local_user_uuid_hasher.finalize()).to_uppercase()); // 64 uppercase character hex

        Ok(ADIProxyAnisetteProvider { adi_proxy })
    }

    fn _get_anisette_headers(&mut self) -> Result<HashMap<String, String>> {
        let adi_proxy = &mut self.adi_proxy as &mut dyn ADIProxy;

        let machine_data = adi_proxy.request_otp(DS_ID)?;

        let mut headers = HashMap::new();
        headers.insert(
            "X-Apple-I-MD".to_string(),
            base64_engine.encode(machine_data.otp),
        );
        headers.insert(
            "X-Apple-I-MD-M".to_string(),
            base64_engine.encode(machine_data.mid),
        );
        headers.insert("X-Apple-I-MD-RINFO".to_string(), "17106176".to_string());
        headers.insert(
            "X-Apple-I-MD-LU".to_string(),
            adi_proxy.get_local_user_uuid(),
        );
        headers.insert(
            "X-Apple-I-SRL-NO".to_string(),
            adi_proxy.get_serial_number(),
        );
        headers.insert(
            "X-Mme-Client-Info".to_string(),
            CLIENT_INFO_HEADER.to_string(),
        );
        headers.insert(
            "X-Mme-Device-Id".to_string(),
            adi_proxy.get_device_identifier(),
        );

        Ok(headers)
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
impl<ProxyType: ADIProxy + 'static> AnisetteHeadersProvider
    for ADIProxyAnisetteProvider<ProxyType>
{
    #[cfg(feature = "async")]
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>> {
        let adi_proxy = &mut self.adi_proxy as &mut dyn ADIProxy;

        if !adi_proxy.is_machine_provisioned(DS_ID) {
            adi_proxy.provision_device().await?;
        }

        self._get_anisette_headers()
    }

    #[cfg(not(feature = "async"))]
    fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>> {
        let adi_proxy = &mut self.adi_proxy as &mut dyn ADIProxy;

        if !adi_proxy.is_machine_provisioned(DS_ID) {
            adi_proxy.provision_device()?;
        }

        self._get_anisette_headers()
    }
}
