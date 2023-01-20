use android_loader::android_library::AndroidLibrary;
use anyhow::Result;
use crate::adi_proxy::{ADIError, ADIProxy, ConfigurableADIProxy, RequestOTPData, StartProvisioningData, SynchronizeData};
use std::ffi::CString;
use android_loader::android_loader::AndroidLoader;

pub struct StoreServicesCoreADIProxy {
    #[allow(dead_code)]
    store_services_core: AndroidLibrary,

    adi_set_android_id: extern "C" fn(id: *const u8, length: u32) -> i32,
    adi_set_provisioning_path: extern "C" fn(path: *const u8) -> i32,

    adi_provisioning_erase: extern "C" fn(ds_id: u64) -> i32,
    adi_synchronize: extern "C" fn(
        ds_id: u64,
        sim: *const u8,
        sim_length: u32,
        out_mid: *mut *const u8,
        out_mid_length: *mut u32,
        out_srm: *mut *const u8,
        out_srm_length: *mut u32,
    ) -> i32,
    adi_provisioning_destroy: extern "C" fn(session: u32) -> i32,
    adi_provisioning_end: extern "C" fn(
        session: u32,
        ptm: *const u8,
        ptm_length: u32,
        tk: *const u8,
        tk_length: u32,
    ) -> i32,
    adi_provisioning_start: extern "C" fn(
        ds_id: u64,
        spim: *const u8,
        spim_length: u32,
        out_cpim: *mut *const u8,
        out_cpim_length: *mut u32,
        out_session: *mut u32,
    ) -> i32,
    adi_get_login_code: extern "C" fn(ds_id: u64) -> i32,
    adi_dispose: extern "C" fn(ptr: *const u8) -> i32,
    adi_otp_request: extern "C" fn(
        ds_id: u64,
        out_mid: *mut *const u8,
        out_mid_size: *mut u32,
        out_otp: *mut *const u8,
        out_otp_size: *mut u32,
    ) -> i32,
}

impl StoreServicesCoreADIProxy {
    fn fetch_libraries(library_path: &str) {

    }

    pub fn new(library_path: &str) -> Result<StoreServicesCoreADIProxy> {
        // Should be safe is the library is correct.
        unsafe {
            let store_services_core = AndroidLoader::load_library("lib/x86_64/libstoreservicescore.so")?;

            let adi_load_library_with_path: extern "C" fn(path: *const u8) -> i32
                = std::mem::transmute(store_services_core.get_symbol("kq56gsgHG6").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?);

            let path = CString::new("lib/x86_64/").unwrap();
            (adi_load_library_with_path)(path.as_ptr() as *const u8);

            let adi_set_android_id = store_services_core.get_symbol("Sph98paBcz").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_set_provisioning_path = store_services_core.get_symbol("nf92ngaK92").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;

            let adi_provisioning_erase = store_services_core.get_symbol("p435tmhbla").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_synchronize = store_services_core.get_symbol("tn46gtiuhw").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_provisioning_destroy = store_services_core.get_symbol("fy34trz2st").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_provisioning_end = store_services_core.get_symbol("uv5t6nhkui").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_provisioning_start = store_services_core.get_symbol("rsegvyrt87").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_get_login_code = store_services_core.get_symbol("aslgmuibau").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_dispose = store_services_core.get_symbol("jk24uiwqrg").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
            let adi_otp_request = store_services_core.get_symbol("qi864985u0").ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;

            Ok(StoreServicesCoreADIProxy {
                store_services_core,

                adi_set_android_id: std::mem::transmute(adi_set_android_id),
                adi_set_provisioning_path: std::mem::transmute(adi_set_provisioning_path),

                adi_provisioning_erase: std::mem::transmute(adi_provisioning_erase),
                adi_synchronize: std::mem::transmute(adi_synchronize),
                adi_provisioning_destroy: std::mem::transmute(adi_provisioning_destroy),
                adi_provisioning_end: std::mem::transmute(adi_provisioning_end),
                adi_provisioning_start: std::mem::transmute(adi_provisioning_start),
                adi_get_login_code: std::mem::transmute(adi_get_login_code),
                adi_dispose: std::mem::transmute(adi_dispose),
                adi_otp_request: std::mem::transmute(adi_otp_request),
            })
        }
    }
}

impl ADIProxy for StoreServicesCoreADIProxy {    fn erase_provisioning(&mut self, ds_id: u64) -> Result<(), ADIError> {
    match (self.adi_provisioning_erase)(ds_id) {
        0 => Ok(()),
        err => Err(ADIError::resolve(err))
    }
}

    fn synchronize(&mut self, ds_id: u64, sim: &[u8]) -> Result<SynchronizeData, ADIError> {
        unsafe {
            let sim_size = sim.len() as u32;
            let sim_ptr = sim.as_ptr();

            let mut mid_size: u32 = 0;
            let mut mid_ptr: *const u8 = std::ptr::null();
            let mut srm_size: u32 = 0;
            let mut srm_ptr: *const u8 = std::ptr::null();

            match (self.adi_synchronize)(ds_id, sim_ptr, sim_size, &mut mid_ptr, &mut mid_size, &mut srm_ptr, &mut srm_size) {
                0 => {
                    let mut mid = vec![0; mid_size as usize];
                    let mut srm = vec![0; srm_size as usize];

                    mid.copy_from_slice(std::slice::from_raw_parts(mid_ptr, mid_size as usize));
                    srm.copy_from_slice(std::slice::from_raw_parts(srm_ptr, srm_size as usize));

                    (self.adi_dispose)(mid_ptr);
                    (self.adi_dispose)(srm_ptr);

                    Ok(SynchronizeData {
                        mid,
                        srm
                    })
                },
                err => Err(ADIError::resolve(err))
            }
        }
    }

    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError> {
        match (self.adi_provisioning_destroy)(session) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err))
        }
    }

    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError> {
        let ptm_size = ptm.len() as u32;
        let ptm_ptr = ptm.as_ptr();

        let tk_size = tk.len() as u32;
        let tk_ptr = tk.as_ptr();

        match (self.adi_provisioning_end)(session, ptm_ptr, ptm_size, tk_ptr, tk_size) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err))
        }
    }

    fn start_provisioning(&mut self, ds_id: u64, spim: &[u8]) -> Result<StartProvisioningData, ADIError> {
        unsafe {
            let spim_size = spim.len() as u32;
            let spim_ptr = spim.as_ptr();

            let mut cpim_size: u32 = 0;
            let mut cpim_ptr: *const u8 = std::ptr::null();

            let mut session: u32 = 0;

            match (self.adi_provisioning_start)(ds_id, spim_ptr, spim_size, &mut cpim_ptr, &mut cpim_size, &mut session) {
                0 => {
                    let mut cpim = vec![0; cpim_size as usize];

                    cpim.copy_from_slice(std::slice::from_raw_parts(cpim_ptr, cpim_size as usize));

                    (self.adi_dispose)(cpim_ptr);

                    Ok(StartProvisioningData {
                        cpim
                    })
                },
                err => Err(ADIError::resolve(err))
            }
        }
    }

    fn is_machine_provisioned(&self, ds_id: u64) -> bool {
        (self.adi_get_login_code)(ds_id) == 0
    }

    fn request_otp(&self, ds_id: u64) -> Result<RequestOTPData, ADIError> {
        unsafe {
            let mut mid_size: u32 = 0;
            let mut mid_ptr: *const u8 = std::ptr::null();
            let mut otp_size: u32 = 0;
            let mut otp_ptr: *const u8 = std::ptr::null();

            match (self.adi_otp_request)(ds_id, &mut mid_ptr, &mut mid_size, &mut otp_ptr, &mut otp_size) {
                0 => {
                    let mut mid = vec![0; mid_size as usize];
                    let mut otp = vec![0; otp_size as usize];

                    mid.copy_from_slice(std::slice::from_raw_parts(mid_ptr, mid_size as usize));
                    otp.copy_from_slice(std::slice::from_raw_parts(otp_ptr, otp_size as usize));

                    (self.adi_dispose)(mid_ptr);
                    (self.adi_dispose)(otp_ptr);

                    Ok(RequestOTPData {
                        mid,
                        otp
                    })
                },
                err => Err(ADIError::resolve(err))
            }
        }
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
        match (self.adi_set_android_id)(identifier.as_ptr(), identifier.len() as u32) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err))
        }
    }

    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError> {
        let path = CString::new(path).unwrap();
        match (self.adi_set_provisioning_path)(path.as_ptr() as *const u8) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err))
        }
    }
}

#[derive(Debug)]
enum ADIStoreSericesCoreErr {
    InvalidLibraryFormat
}

impl std::fmt::Display for ADIStoreSericesCoreErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ADIStoreSericesCoreErr {}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::adi_proxy::ADIProxyAnisetteProvider;
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::store_services_core::StoreServicesCoreADIProxy;

    #[test]
    fn fetch_anisette_ssc() -> Result<()> {
        let provider = ADIProxyAnisetteProvider::new(StoreServicesCoreADIProxy::new("lib/")?);
        println!("SSC headers: {:?}", (&provider as &dyn AnisetteHeadersProvider).get_authentication_headers()?);
        Ok(())
    }
}
