use icloud_auth::{anisette::AnisetteData, AppleAccount};

pub struct XcodeSession {
    pub dsid: String,
    pub auth_token: String,
    pub anisette: AnisetteData,
}

impl XcodeSession {
    pub fn with(account: &AppleAccount) -> XcodeSession {
        let spd = account.spd.as_ref().unwrap();
        let dsid = spd.get("dsid").unwrap().as_string().unwrap();
        let auth_token = spd.get("authoken").unwrap().as_string().unwrap();
    }
}
