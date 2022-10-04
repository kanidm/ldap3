

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
    /// Check authentication (bind) to a directory server
    Whoami,
    /// Sync a listed subtree
    Syncrepl {
        basedn: String,
        #[clap(long)]
        cookie: Option<String>,
        // #[clap(value_enum, default_value_t, long)]
        // mode: SyncRequestMode
    },
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Ldap Client Utility")]
struct LdapOpt {
    #[structopt(short, long)]
    /// Display extended infomation during runtime.
    verbose: bool,

    #[clap(short = 'H', long = "url")]
    url: url::Url,

    #[clap(short = 'j', long = "json")]
    json: bool,

    #[clap(short = 'D', long = "dn")]
    bind_dn: Option<String>,

    #[clap(short = 'w', long = "pass")]
    bind_passwd: Option<String>,

    #[clap(subcommand)]
    /// The ldap action to perform
    action: LdapAction
}

