#![allow(dead_code)]

use std::env;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};

include!("src/ldap_opt.rs");
include!("src/cldap_opt.rs");
include!("src/ldap_debug_opt.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    // Will be the form /Volumes/ramdisk/rs/debug/build/kanidm-8aadc4b0821e9fe7/out
    // We want to get to /Volumes/ramdisk/rs/debug/completions
    let comp_dir = PathBuf::from(outdir)
        .ancestors()
        .nth(2)
        .map(|p| p.join("completions"))
        .expect("Unable to process completions path");

    if !comp_dir.exists() {
        std::fs::create_dir(&comp_dir).expect("Unable to create completions dir");
    }

    generate_to(
        Shell::Bash,
        &mut LdapOpt::command(),
        "ldap",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut LdapOpt::command(),
        "ldap",
        comp_dir.clone(),
    )
    .ok();

    generate_to(
        Shell::Bash,
        &mut CldapOpt::command(),
        "cldap",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut CldapOpt::command(),
        "cldap",
        comp_dir.clone(),
    )
    .ok();

    generate_to(
        Shell::Bash,
        &mut LdapDebugOpt::command(),
        "ldap_debug",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut LdapDebugOpt::command(),
        "ldap_debug",
        comp_dir,
    )
    .ok();

    println!("cargo:rerun-if-changed=src/ldap_opt.rs");
    println!("cargo:rerun-if-changed=src/cldap_opt.rs");
    println!("cargo:rerun-if-changed=src/ldap_debug_opt.rs");
}
