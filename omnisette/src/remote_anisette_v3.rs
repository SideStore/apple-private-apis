
// Implementing the SideStore Anisette v3 protocol

use std::{collections::HashMap, io::Cursor};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use log::debug;
use plist::{Data, Dictionary};
use reqwest::{Client, ClientBuilder, RequestBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use rand::Rng;
use sha2::{Sha256, Digest};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;
use futures_util::{stream::StreamExt, SinkExt};
use std::fmt::Write;
use base64::Engine;
use async_trait::async_trait;

use crate::anisette_headers_provider::AnisetteHeadersProvider;


fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    Ok(s.try_into().unwrap())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(data.trim()).unwrap()
}



#[derive(Deserialize)]
struct AnisetteClientInfo {
    client_info: String,
    user_agent: String,
}

#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_16")]
    keychain_identifier: [u8; 16],
    #[serde(serialize_with = "bin_serialize_opt", deserialize_with = "bin_deserialize_opt")]
    adi_pb: Option<Vec<u8>>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::thread_rng().gen::<[u8; 16]>(),
            adi_pb: None
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn is_provisioned(&self) -> bool {
        self.adi_pb.is_some()
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}
pub struct AnisetteClient {
    client_info: AnisetteClientInfo,
    url: String
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    local_user_id: String,
    device_unique_identifier: String
}

impl AnisetteData {
    pub fn get_headers(&self) -> HashMap<String, String> {
        // TODO time headers
        HashMap::from_iter([
            ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
            ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
            ("X-Mme-Device-Id".to_string(), self.device_unique_identifier.clone()),
            ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
            ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
            ("X-Mme-Client-Info".to_string(), self.device_description.clone()),
        ].into_iter())
    }
}

fn make_reqwest() -> Result<Client> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .danger_accept_invalid_certs(true) // TODO: pin the apple certificate
        .build()?)
}

impl AnisetteClient {
    pub async fn new(url: String) -> Result<AnisetteClient> {
        let path = format!("{}/v3/client_info", url);
        let http_client = make_reqwest()?;
        let client_info = http_client.get(path)
            .send().await?
            .json::<AnisetteClientInfo>().await?;
        Ok(AnisetteClient {
            client_info,
            url
        })
    }

    fn build_apple_request(&self, state: &AnisetteState, builder: RequestBuilder) -> RequestBuilder {
        // TODO time headers
        builder.header("X-Mme-Client-Info", &self.client_info.client_info)
            .header("User-Agent", &self.client_info.user_agent)
            .header("Content-Type", "text/x-xml-plist")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
    }

    pub async fn get_headers(&self, state: &AnisetteState) -> Result<AnisetteData> {
        let path = format!("{}/v3/get_headers", self.url);
        let http_client = make_reqwest()?;

        #[derive(Serialize)]
        struct GetHeadersBody {
            identifier: String,
            adi_pb: String,
        }
        let body = GetHeadersBody {
            identifier: base64_encode(&state.keychain_identifier),
            adi_pb: base64_encode(state.adi_pb.as_ref().ok_or(anyhow!("AnisetteNotProvisioned"))?),
        };

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum AnisetteHeaders {
            GetHeadersError {
                message: String
            },
            Headers {
                #[serde(rename = "X-Apple-I-MD-M")]
                machine_id: String,
                #[serde(rename = "X-Apple-I-MD")]
                one_time_password: String,
                #[serde(rename = "X-Apple-I-MD-RINFO")]
                routing_info: String,
            }
        }

        let headers = http_client.post(path)
            .json(&body)
            .send().await?
            .json::<AnisetteHeaders>().await?;
        match headers {
            AnisetteHeaders::GetHeadersError { message } => {
                if message.contains("-45061") {
                    Err(anyhow!("AnisetteNotProvisioned"))
                } else {
                    panic!("Unknown error {}", message)
                }
            },
            AnisetteHeaders::Headers { machine_id, one_time_password, routing_info } => {
                Ok(AnisetteData {
                    machine_id,
                    one_time_password,
                    routing_info,
                    device_description: self.client_info.client_info.clone(),
                    local_user_id: base64_encode(&state.md_lu()),
                    device_unique_identifier: state.device_id()
                })
            }
        }
    }

    pub async fn provision(&self, state: &mut AnisetteState) -> Result<()> {
        debug!("Provisioning Anisette");
        let http_client = make_reqwest()?;
        let resp = self.build_apple_request(&state, http_client.get("https://gsa.apple.com/grandslam/GsService2/lookup"))
            .send().await?;
        let text = resp.text().await?;

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let urls = protocol_val.as_dictionary().unwrap().get("urls").unwrap().as_dictionary().unwrap();

        let start_provisioning_url = urls.get("midStartProvisioning").unwrap().as_string().unwrap();
        let end_provisioning_url = urls.get("midFinishProvisioning").unwrap().as_string().unwrap();
        debug!("Got provisioning urls: {} and {}", start_provisioning_url, end_provisioning_url);

        let provision_ws_url = format!("{}/v3/provisioning_session", self.url).replace("https://", "wss://");
        let (mut connection, _) = connect_async(&provision_ws_url).await?;


        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum ProvisionInput {
            GiveIdentifier,
            GiveStartProvisioningData,
            GiveEndProvisioningData {
                #[allow(dead_code)] // it's not even dead, rust just has problems
                cpim: String
            },
            ProvisioningSuccess {
                #[allow(dead_code)] // it's not even dead, rust just has problems
                adi_pb: String
            }
        }

        loop {
            let Some(Ok(data)) = connection.next().await else {
                continue
            };
            if data.is_text() {
                let txt = data.to_text().unwrap();
                let msg: ProvisionInput = serde_json::from_str(txt)?;
                match msg {
                    ProvisionInput::GiveIdentifier => {
                        #[derive(Serialize)]
                        struct Identifier {
                            identifier: String // base64
                        }
                        let identifier = Identifier { identifier: base64_encode(&state.keychain_identifier) };
                        connection.send(Message::Text(serde_json::to_string(&identifier)?)).await?;
                    },
                    ProvisionInput::GiveStartProvisioningData => {
                        let http_client = make_reqwest()?;
                        let body_data = ProvisionBodyData { header: Dictionary::new(), request: Dictionary::new() };
                        let resp = self.build_apple_request(state, http_client.post(start_provisioning_url))
                            .body(plist_to_string(&body_data)?)
                            .send().await?;
                        let text = resp.text().await?;

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let spim = protocol_val.as_dictionary().unwrap().get("Response").unwrap().as_dictionary().unwrap()
                            .get("spim").unwrap().as_string().unwrap();
                        
                        debug!("GiveStartProvisioningData");
                        #[derive(Serialize)]
                        struct Spim {
                            spim: String // base64
                        }
                        let spim = Spim { spim: spim.to_string() };
                        connection.send(Message::Text(serde_json::to_string(&spim)?)).await?;
                    },
                    ProvisionInput::GiveEndProvisioningData { cpim } => {
                        let http_client = make_reqwest()?;
                        let body_data = ProvisionBodyData { header: Dictionary::new(), request: Dictionary::from_iter([("cpim", cpim)].into_iter()) };
                        let resp = self.build_apple_request(state, http_client.post(end_provisioning_url))
                            .body(plist_to_string(&body_data)?)
                            .send().await?;
                        let text = resp.text().await?;

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let response = protocol_val.as_dictionary().unwrap().get("Response").unwrap().as_dictionary().unwrap();

                        debug!("GiveEndProvisioningData");
                        
                        #[derive(Serialize)]
                        struct EndProvisioning<'t> {
                            ptm: &'t str,
                            tk: &'t str,
                        }
                        let end_provisioning = EndProvisioning {
                            ptm: response.get("ptm").unwrap().as_string().unwrap(),
                            tk: response.get("tk").unwrap().as_string().unwrap(),
                        };
                        connection.send(Message::Text(serde_json::to_string(&end_provisioning)?)).await?;
                    },
                    ProvisionInput::ProvisioningSuccess { adi_pb } => {
                        debug!("ProvisioningSuccess");
                        state.adi_pb = Some(base64_decode(&adi_pb));
                        connection.close(None).await?;
                        break;
                    }
                }
            } else if data.is_close() {
                break;
            }
        }

        Ok(())
    }
}


pub struct RemoteAnisetteProviderV3 {
    client: AnisetteClient,
    pub state: AnisetteState,
}

impl RemoteAnisetteProviderV3 {
    pub async fn new(url: String, mut state: AnisetteState) -> Result<RemoteAnisetteProviderV3> {
        let client = AnisetteClient::new(url).await?;
        if !state.is_provisioned() {
            client.provision(&mut state).await?;
        }
        Ok(RemoteAnisetteProviderV3 {
            client,
            state
        })
    }
}

#[async_trait(?Send)]
impl AnisetteHeadersProvider for RemoteAnisetteProviderV3 {
    async fn get_anisette_headers(
        &mut self,
        _skip_provisioning: bool,
    ) -> Result<HashMap<String, String>> {
        let data = self.client.get_headers(&self.state).await?;
        Ok(data.get_headers())
    }
}

#[cfg(test)]
mod tests {
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::remote_anisette_v3::{AnisetteState, RemoteAnisetteProviderV3};
    use crate::DEFAULT_ANISETTE_URL_V3;
    use anyhow::Result;
    use log::info;

    #[tokio::test]
    async fn fetch_anisette_remote_v3() -> Result<()> {
        crate::tests::init_logger();

        let mut provider = RemoteAnisetteProviderV3::new(DEFAULT_ANISETTE_URL_V3.to_string(), AnisetteState::new()).await?;
        info!(
            "Remote headers: {:?}",
            (&mut provider as &mut dyn AnisetteHeadersProvider).get_authentication_headers().await?
        );
        Ok(())
    }
}

