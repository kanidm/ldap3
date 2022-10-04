// use clap::{Args, Subcommand};

#[derive(Debug, clap::Parser)]
#[clap(about = "Connectionless Ldap Client Utility")]
enum CldapOpt {
    Search
}

