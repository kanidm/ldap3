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

include!("./ldap_opt.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = LdapOpt::from_args();
    ldap3_cli_common::start_tracing(opt.verbose);
    info!("ldap command line utility");

    let timeout = Duration::from_secs(1);

    let (bind_dn, bind_passwd) = if let Some(dn) = opt.bind_dn {
        if let Some(pw) = opt.bind_passwd {
            (dn.clone(), pw.clone())
        } else if opt.json {
            let e = LdapError::PasswordNotFound;
            println!(
                "{}",
                serde_json::to_string_pretty(&e).expect("CRITICAL: Serialisation Fault")
            );
            std::process::exit(e as i32);
        } else {
            let pw = match rpassword::prompt_password(&format!("Enter password for {}: ", dn)) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to get bind password - {}", e);
                    std::process::exit(LdapError::PasswordNotFound as i32);
                }
            };
            (dn.clone(), pw)
        }
    } else {
        if opt.bind_passwd.is_some() {
            let e = LdapError::AnonymousInvalidState;
            if opt.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&e).expect("CRITICAL: Serialisation Fault")
                );
            } else {
                error!("Anonymous does not take a password - {}", e);
            }
            std::process::exit(e as i32);
        } else {
            ("".to_string(), "".to_string())
        }
    };

    let mut client = match LdapClient::new(&opt.url, timeout).await {
        Ok(c) => c,
        Err(e) => {
            if opt.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&e).expect("CRITICAL: Serialisation Fault")
                )
            } else {
                error!("Failed to create ldap client - {}", e);
            }
            std::process::exit(e as i32);
        }
    };

    // The first message after connect is always a bind.
    if let Err(e) = client.bind(bind_dn, bind_passwd).await {
        if opt.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&e).expect("CRITICAL: Serialisation Fault")
            )
        } else {
            error!("Failed to create ldap client - {}", e);
        }
        std::process::exit(e as i32);
    };

    match opt.action {
        LdapAction::Search { basedn, filter } => {
            let filter = ldap3_client::filter::parse_ldap_filter_str(&filter)
                .map_err(|e| {
                    error!(?e);
                })
                .expect("Invalid filter");

            match client.search(basedn, filter).await {
                Ok(search_result) => {
                    if opt.json {
                    } else {
                        for ent in &search_result.entries {
                            println!("dn: {}", ent.dn);
                            for (attr, vals) in &ent.attrs {
                                for val in vals {
                                    println!("{}: {}", attr, val);
                                }
                            }
                            println!("");
                        }
                    }
                }
                Err(e) => {
                    if opt.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&e)
                                .expect("CRITICAL: Serialisation Fault")
                        )
                    } else {
                        error!("Failed to send syncrepl request - {}", e);
                    }
                    std::process::exit(e as i32);
                }
            }
        }
        LdapAction::Whoami => match client.whoami().await {
            Ok(Some(dn)) => {
                if dn.is_empty() {
                    println!("dn: anonymous");
                } else {
                    println!("dn: {}", dn);
                }
            }
            Ok(None) => {
                println!("dn: <N/A>");
            }
            Err(e) => {
                if opt.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&e).expect("CRITICAL: Serialisation Fault")
                    )
                } else {
                    error!("Failed to send whoami request - {}", e);
                }
                std::process::exit(e as i32);
            }
        },
        LdapAction::Syncrepl {
            basedn,
            cookie,
            // mode,
        } => {
            /*
            let mode = match mode {
                SyncRequestMode::RefreshOnly => ldapcli::proto::SyncRequestMode::RefreshOnly,
                SyncRequestMode::RefreshAndPersist => {
                    ldapcli::proto::SyncRequestMode::RefreshAndPersist
                }
            };
            */

            let mode = proto::SyncRequestMode::RefreshOnly;

            let cookie = if let Some(cookie) = cookie {
                match base64::decode_config(&cookie, base64::STANDARD_NO_PAD) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!(?e, "Failed to parse cookie");
                        return;
                    }
                }
            } else {
                None
            };

            match client.syncrepl(basedn, cookie, mode).await {
                Ok(sync_repl) => {
                    // what do?
                    for ent in &sync_repl.entries {
                        println!("entryuuid: {}", ent.entry_uuid);
                        println!("syncstate: {:?}", ent.state);
                        println!("dn: {}", ent.entry.dn);
                        for (attr, vals) in &ent.entry.attrs {
                            for val in vals {
                                println!("{}: {}", attr, val);
                            }
                        }
                        println!("");
                    }
                    for entry_uuid in &sync_repl.delete_uuids {
                        println!("delete entryuuid: {}", entry_uuid);
                    }
                    if !sync_repl.present_uuids.is_empty() {
                        println!("");
                    }
                    for entry_uuid in &sync_repl.present_uuids {
                        println!("delete entryuuid: {}", entry_uuid);
                        println!("");
                    }
                    println!("");
                    println!("refresh_deletes: {}", sync_repl.refresh_deletes);
                    println!(
                        "cookie: {}",
                        sync_repl.cookie.unwrap_or_else(|| "NONE".to_string())
                    );
                }
                Err(e) => {
                    if opt.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&e)
                                .expect("CRITICAL: Serialisation Fault")
                        )
                    } else {
                        error!("Failed to send syncrepl request - {}", e);
                    }
                    std::process::exit(e as i32);
                }
            }
        }
        LdapAction::AdDirsync { basedn, cookie } => {
            let cookie = if let Some(cookie) = cookie {
                match base64::decode_config(&cookie, base64::STANDARD_NO_PAD) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!(?e, "Failed to parse cookie");
                        return;
                    }
                }
            } else {
                None
            };

            match client.ad_dirsync(basedn, cookie).await {
                Ok(sync_repl) => {
                    // what do?
                    for ent in &sync_repl.entries {
                        // println!("entryuuid: {}", ent.entry_uuid);
                        println!("dn: {}", ent.entry.dn);
                        for (attr, vals) in &ent.entry.attrs {
                            for val in vals {
                                println!("{}: {}", attr, val);
                            }
                        }
                        println!("");
                    }
                    for entry_uuid in &sync_repl.delete_uuids {
                        println!("delete entryuuid: {}", entry_uuid);
                    }
                    if !sync_repl.present_uuids.is_empty() {
                        println!("");
                    }
                    for entry_uuid in &sync_repl.present_uuids {
                        println!("delete entryuuid: {}", entry_uuid);
                        println!("");
                    }
                    println!("");
                    println!(
                        "cookie: {}",
                        sync_repl.cookie.unwrap_or_else(|| "NONE".to_string())
                    );
                }
                Err(e) => {
                    if opt.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&e)
                                .expect("CRITICAL: Serialisation Fault")
                        )
                    } else {
                        error!("Failed to send syncrepl request - {}", e);
                    }
                    std::process::exit(e as i32);
                }
            }
        }
    }
}
