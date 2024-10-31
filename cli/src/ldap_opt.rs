/*
#[derive(clap::ValueEnum, Debug, Clone)]
enum SyncRequestMode {
    RefreshOnly,
    RefreshAndPersist
}

impl Default for SyncRequestMode {
    fn default() -> Self {
        SyncRequestMode::RefreshOnly
    }
}
*/

use url::Url;

#[derive(Debug, clap::Subcommand)]
enum LdapAction {
    /// Search a directory server
    Search {
        /// Search this basedn,
        basedn: String,

        // /// scope
        // scope
        /// Execute this query
        filter: String,
    },
    /*
    FilterHelper {
        /// The filter to examine.
        filter: String,
        /// The filter to compare to.
        filter_comp: Option<String>,
    },
    */
    /// Check authentication (bind) to a directory server
    Whoami,
    /// Sync a listed subtree from FreeIPA, OpenLDAP or 389-ds
    Syncrepl {
        basedn: String,
        #[clap(long)]
        cookie: Option<String>,
        // #[clap(value_enum, default_value_t, long)]
        // mode: SyncRequestMode
    },
    /// Sync a directory partition from Active Directory
    AdDirsync {
        basedn: String,
        #[clap(long)]
        cookie: Option<String>,
    },
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Ldap Client Utility")]
struct LdapOpt {
    #[structopt(short, long)]
    /// Display extended information during runtime.
    verbose: bool,

    #[clap(short = 'H', long = "url")]
    url: Url,

    #[clap(short = 'j', long = "json")]
    json: bool,

    #[clap(short = 'D', long = "dn")]
    bind_dn: Option<String>,

    #[clap(short = 'w', long = "pass")]
    bind_passwd: Option<String>,

    #[clap(short = 'C', long = "ca")]
    ca_cert: Option<String>,

    #[clap(subcommand)]
    /// The ldap action to perform
    action: LdapAction,
}
