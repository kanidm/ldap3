use clap::Parser;
use ldap3_client::*;

include!("./cldap_opt.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    ldap3_cli_common::start_tracing(true);
    trace!("cldap command line utility");

    let opt = CldapOpt::from_args();
}
