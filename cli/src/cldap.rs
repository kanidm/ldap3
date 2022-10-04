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

include!("./cldap_opt.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    ldap3_cli_common::start_tracing(true);
    trace!("cldap command line utility");

    let _opt = CldapOpt::from_args();
}
