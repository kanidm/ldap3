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

use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

pub fn start_tracing(verbose: bool) {
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| {
            if verbose {
                EnvFilter::try_new("info")
            } else {
                EnvFilter::try_new("warn")
            }
        })
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}
