use apple_codesign::{
    cryptography::{parse_pfx_data, PrivateKey},
    AppleCodesignError, SigningSettings, UnifiedSigner,
};
use paris_log::{debug, warn};

pub mod dummy_bundle_id;

/// Signs the .app using apple-codesign/rcodesign. This will also automatically call `add_dummy_bundle_ids`
/// ### Arguments
/// - `app_path`: Path to the .app
/// - `bundle_id`: The bundle ID of the .app. This will probably have team ID added to it, but you are responsible for that
/// - `certificate`: Bytes of a .p12 certificate to use when signing
/// - `certificate_password`: The password for `certificate`
pub fn sign_app(
    app_path: &str,
    bundle_id: &str,
    certificate: &[u8],
    certificate_password: &str,
) -> Result<(), AppleCodesignError> {
    debug!("Adding dummy bundle IDs");
    dummy_bundle_id::add_dummy_bundle_ids(app_path, bundle_id);
    debug!("Done adding dummy bundle IDs!");

    let (cert, key) = parse_pfx_data(certificate, certificate_password)?;
    drop(certificate);
    drop(certificate_password);

    let mut settings = SigningSettings::default();
    settings.set_signing_key(key.as_key_info_signer(), cert);
    match settings.chain_apple_certificates() {
        Some(certs) => {
            for cert in certs {
                debug!(
                    "Automatically registered Apple CA certificate: {}",
                    cert.subject_common_name()
                        .unwrap_or_else(|| "default".into())
                );
            }
        }
        None => warn!("Didn't register any certificates"),
    }

    // unfortunately the const in rcodesign isn't public
    settings.set_time_stamp_url("http://timestamp.apple.com/ts01")?;

    match settings.set_team_id_from_signing_certificate() {
        Some(team_id) => debug!(
            "Automatically setting team ID from signing certificate: {}",
            team_id
        ),
        None => warn!(
            "<yellow><warn></> TEAM ID WAS NOT SET!! THIS COULD BE AN ISSUE! <yellow><warn></>"
        ),
    }

    // don't sign embedded.mobileprovision files
    settings.add_path_exclusion("**/embedded.mobileprovision")?;

    let signer = UnifiedSigner::new(settings);

    debug!("Signing at {app_path}");
    signer.sign_path_in_place(app_path)?;
    debug!("Done signing!");

    Ok(())
}

#[cfg(test)]
mod tests {
    pub fn logger() {
        use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

        if TermLogger::init(
            LevelFilter::Trace,
            ConfigBuilder::new()
                .set_target_level(LevelFilter::Error)
                .add_filter_allow_str("apple_codesign_wrapper")
                .add_filter_allow_str("apple_codesign")
                .add_filter_ignore_str("apple_codesign::code_resources") // reduce log spam a bit
                .build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .is_ok()
        {}
    }

    #[test]
    fn sign_app() {
        crate::tests::logger();

        super::sign_app(
            "TODO.app",
            "TODO",
            std::fs::read("TODO.p12").unwrap().as_slice(),
            "",
        )
        .unwrap();
    }
}
