#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]

use clap::Parser;
use ldap3_client::*;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

include!("ldap_debug_opt.rs");

fn main() {
    let opt = LdapDebugOpt::from_args();
    ldap3_cli_common::start_tracing(opt.verbose);
    info!("ldap debugging assistance tool");

    if cfg!(feature = "strict") {
        info!("strict is enabled, some features may not work");
    }

    match opt.action {
        LdapDebugAction::BerDump(ber_dump_opts) => {
            let file = match File::open(ber_dump_opts.path) {
                Ok(f) => f,
                Err(e) => {
                    error!(?e);
                    return;
                }
            };
            let reader = BufReader::new(file);

            match ber_dump_opts.format {
                DumpFormat::OpenLDAPMemDump => {
                    info!("Treated as OpenLDAPMemDump");
                    let bytes: Vec<u8> = match ron::de::from_reader(reader) {
                        Ok(b) => b,
                        Err(e) => {
                            error!(?e);
                            return;
                        }
                    };
                    trace!(?bytes);
                    match proto::LdapMsg::try_from_openldap_mem_dump(&bytes) {
                        Ok(msg) => info!(?msg),
                        Err(e) => error!(?e, "Failed to decode memory dump"),
                    }
                }
            }
        }
    }
}
