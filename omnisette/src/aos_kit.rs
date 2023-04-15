use crate::anisette_headers_provider::AnisetteHeadersProvider;
use anyhow::Result;

use dlopen2::symbor::Library;
use objc::{msg_send, runtime::Class, sel, sel_impl};
use objc_foundation::{INSString, NSObject, NSString};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
pub struct AOSKitAnisetteProvider<'lt> {
    aos_utilities: &'lt Class,
    ak_device: &'lt Class,
}

impl<'lt> AOSKitAnisetteProvider<'lt> {
    pub fn new() -> Result<AOSKitAnisetteProvider<'lt>> {
        Library::open("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit")?;
        Library::open("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit")?;
        Ok(AOSKitAnisetteProvider {
            aos_utilities: Class::get("AOSUtilities").ok_or(AOSKitError::ClassLoadFailed)?,
            ak_device: Class::get("AKDevice").ok_or(AOSKitError::ClassLoadFailed)?,
        })
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
impl<'lt> AnisetteHeadersProvider for AOSKitAnisetteProvider<'lt> {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_anisette_headers(
        &mut self,
        _skip_provisioning: bool,
    ) -> Result<HashMap<String, String>> {
        let mut headers_map = HashMap::new();

        let headers: *const NSObject = unsafe {
            msg_send![self.aos_utilities, retrieveOTPHeadersForDSID: NSString::from_str("-2")]
        };

        let otp: *const NSString =
            unsafe { msg_send![headers, valueForKey: NSString::from_str("X-Apple-MD")] };
        headers_map.insert(
            "X-Apple-I-MD".to_string(),
            unsafe { (*otp).as_str() }.to_string(),
        );

        let mid: *const NSString =
            unsafe { msg_send![headers, valueForKey: NSString::from_str("X-Apple-MD-M")] };
        headers_map.insert(
            "X-Apple-I-MD-M".to_string(),
            unsafe { (*mid).as_str() }.to_string(),
        );

        let machine_serial_number: *const NSString =
            unsafe { msg_send![self.aos_utilities, machineSerialNumber] };
        headers_map.insert(
            "X-Apple-SRL-NO".to_string(),
            unsafe { (*machine_serial_number).as_str() }.to_string(),
        );

        let current_device: *const NSObject = unsafe { msg_send![self.ak_device, currentDevice] };

        let local_user_uuid: *const NSString = unsafe { msg_send![current_device, localUserUUID] };
        headers_map.insert(
            "X-Apple-I-MD-LU".to_string(),
            unsafe { (*local_user_uuid).as_str() }.to_string(),
        );

        let locale: *const NSObject = unsafe { msg_send![current_device, locale] };
        let locale: *const NSString = unsafe { msg_send![locale, localeIdentifier] };
        headers_map.insert(
            "X-Apple-Locale".to_string(),
            unsafe { (*locale).as_str() }.to_string(),
        ); // FIXME maybe not the right header name

        let server_friendly_description: *const NSString =
            unsafe { msg_send![current_device, serverFriendlyDescription] };
        headers_map.insert(
            "X-Mme-Client-Info".to_string(),
            unsafe { (*server_friendly_description).as_str() }.to_string(),
        );

        let unique_device_identifier: *const NSString =
            unsafe { msg_send![current_device, uniqueDeviceIdentifier] };
        headers_map.insert(
            "X-Mme-Device-Id".to_string(),
            unsafe { (*unique_device_identifier).as_str() }.to_string(),
        );

        Ok(headers_map)
    }
}

#[derive(Debug)]
enum AOSKitError {
    ClassLoadFailed,
}

impl Display for AOSKitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for AOSKitError {}

#[cfg(all(test, not(feature = "async")))]
mod tests {
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::aos_kit::AOSKitAnisetteProvider;
    use anyhow::Result;
    use log::info;

    #[test]
    fn fetch_anisette_aoskit() -> Result<()> {
        crate::tests::init_logger();

        let mut provider = AOSKitAnisetteProvider::new()?;
        info!(
            "AOSKit headers: {:?}",
            (&mut provider as &mut dyn AnisetteHeadersProvider).get_authentication_headers()?
        );
        Ok(())
    }
}
