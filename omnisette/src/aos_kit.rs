use anyhow::{Result, Ok};
use std::collections::HashMap;
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use dlopen2::symbor::Library;
use objc::{msg_send, runtime::Class, sel, sel_impl};
use objc_foundation::{INSString, NSObject, NSString};

struct AOSKitAnisetteProvider {
    aos_kit: Library,
    auth_kit: Library,
    aos_utilities: Class,
    ak_device: Class
}

impl AnisetteHeadersProvider for AOSKitAnisetteProvider {
    fn new() -> Result<AOSKitAnisetteProvider> {
        Ok(AOSKitAnisetteProvider {
            aos_kit: Library::open("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit")?,
            auth_kit: Library::open("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit")?,
            aos_utilities: Class::get("AOSUtilities")?,
            ak_device: Class::get("AKDevice")?
        })
    }

    fn get_anisette_headers(&self) -> HashMap<String, String> {
        let headers_map = HashMap::new();

        let headers: *const NSObject =
            unsafe { msg_send![self.aos_utilities, retrieveOTPHeadersForDSID: NSString::from_str("-2")] };

        let otp: *const NSString =
            unsafe { msg_send![headers, valueForKey: NSString::from_str("X-Apple-MD")] };
        headers_map["X-Apple-I-MD"] = unsafe { (*otp).as_str() };

        let mid: *const NSString =
            unsafe { msg_send![headers, valueForKey: NSString::from_str("X-Apple-MD-M")] };
        headers_map["X-Apple-I-MD-M"] = unsafe { (*mid).as_str() };

        let machine_serial_number: *const NSString =
            unsafe { msg_send![aos_utilities, machineSerialNumber] };
        headers_map["X-Apple-SRL-NO"] = unsafe { (*machine_serial_number).as_str() };

        let current_device: *const NSObject = unsafe { msg_send![self.ak_device, currentDevice] };

        let local_user_uuid: *const NSString = unsafe { msg_send![current_device, localUserUUID] };
        headers_map["X-Apple-I-MD-LU"] = unsafe { (*local_user_uuid).as_str() };

        let locale: *const NSObject = unsafe { msg_send![current_device, locale] };
        let locale: *const NSString = unsafe { msg_send![locale, localeIdentifier] };
        headers_map["X-Apple-Locale"] = unsafe { (*locale).as_str() }; // FIXME maybe not the right header name

        let server_friendly_description: *const NSString =
            unsafe { msg_send![current_device, serverFriendlyDescription] };
        headers_map["X-Mme-Client-Info"] = unsafe { (*server_friendly_description).as_str() };

        let unique_device_identifier: *const NSString =
            unsafe { msg_send![current_device, uniqueDeviceIdentifier] };
        headers_map["X-Mme-Device-Id"] = unsafe { (*unique_device_identifier).as_str() };

        headers_map
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::adi_proxy::ADIProxyAnisetteProvider;
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::aos_kit::AOSKitAnisetteProvider;

    #[test]
    fn fetch_anisette_aoskit() -> Result<()> {
        AOSKitAnisetteProvider::new()?.get_anisette_headers();
        Ok(())
    }
}
