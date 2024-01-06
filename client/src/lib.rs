#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]

use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time;
pub use tokio::time::Duration;
pub use tracing::{debug, error, info, span, trace, warn};

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;

use ldap3_proto::proto::*;
use ldap3_proto::LdapCodec;
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tokio_openssl::SslStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use std::fmt;
use url::Url;
use uuid::Uuid;

use base64::{engine::general_purpose, Engine as _};

pub use ldap3_proto::filter;
pub use ldap3_proto::proto;

mod addirsync;
mod search;
mod syncrepl;

pub use search::LdapSearchResult;
pub use syncrepl::{LdapSyncRepl, LdapSyncReplEntry, LdapSyncStateValue};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[repr(i32)]
pub enum LdapError {
    InvalidUrl = -1,
    LdapiNotSupported = -2,
    UseCldapTool = -3,
    ResolverError = -4,
    ConnectError = -5,
    TlsError = -6,
    PasswordNotFound = -7,
    AnonymousInvalidState = -8,
    TransportWriteError = -9,
    TransportReadError = -10,
    InvalidProtocolState = -11,
    FileIOError = -12,

    UnavailableCriticalExtension = 12,
    InvalidCredentials = 49,
    InsufficentAccessRights = 50,
    UnwillingToPerform = 53,
    EsyncRefreshRequired = 4096,
    NotImplemented = 9999,
}

impl From<LdapResultCode> for LdapError {
    fn from(code: LdapResultCode) -> Self {
        match code {
            LdapResultCode::InvalidCredentials => LdapError::InvalidCredentials,
            LdapResultCode::InsufficentAccessRights => LdapError::InsufficentAccessRights,
            LdapResultCode::EsyncRefreshRequired => LdapError::EsyncRefreshRequired,
            LdapResultCode::UnavailableCriticalExtension => LdapError::UnavailableCriticalExtension,
            LdapResultCode::UnwillingToPerform => LdapError::UnwillingToPerform,
            err => {
                error!("{:?} not implemented yet!!", err);
                LdapError::NotImplemented
            }
        }
    }
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapError::InvalidUrl => write!(f, "Invalid URL"),
            LdapError::LdapiNotSupported => write!(f, "Ldapi Not Supported"),
            LdapError::UseCldapTool => write!(f, "Use cldap tool for cldap:// urls"),
            LdapError::ResolverError => write!(f, "Failed to resolve hostname or invalid ip"),
            LdapError::ConnectError => write!(f, "Failed to connect to host"),
            LdapError::TlsError => write!(f, "Failed to establish TLS"),
            LdapError::PasswordNotFound => write!(f, "No password available for bind"),
            LdapError::AnonymousInvalidState => write!(f, "Invalid Anonymous bind state"),
            LdapError::InvalidProtocolState => {
                write!(f, "The LDAP server sent a response we did not expect")
            }
            LdapError::FileIOError => {
                write!(f, "An error occured while accessing a file")
            }
            LdapError::TransportReadError => {
                write!(f, "An error occured reading from the transport")
            }
            LdapError::TransportWriteError => {
                write!(f, "An error occured writing to the transport")
            }
            LdapError::UnavailableCriticalExtension => write!(f, "An extension marked as critical was not available"),
            LdapError::InvalidCredentials => write!(f, "Invalid DN or Password"),
            LdapError::InsufficentAccessRights => write!(f, "Insufficent Access"),
            LdapError::UnwillingToPerform => write!(f, "Too many failures, server is unwilling to perform the operation."),
            LdapError::EsyncRefreshRequired => write!(f, "An initial content sync is required. The current cookie should be considered invalid."),
            LdapError::NotImplemented => write!(f, "An error occurred, but we haven't implemented code to handle this error yet.")
        }
    }
}

pub type LdapResult<T> = Result<T, LdapError>;

enum LdapReadTransport {
    Plain(FramedRead<ReadHalf<TcpStream>, LdapCodec>),
    Tls(FramedRead<ReadHalf<SslStream<TcpStream>>, LdapCodec>),
}

impl fmt::Debug for LdapReadTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapReadTransport::Plain(_) => f
                .debug_struct("LdapReadTransport")
                .field("type", &"plain")
                .finish(),
            LdapReadTransport::Tls(_) => f
                .debug_struct("LdapReadTransport")
                .field("type", &"tls")
                .finish(),
        }
    }
}

enum LdapWriteTransport {
    Plain(FramedWrite<WriteHalf<TcpStream>, LdapCodec>),
    Tls(FramedWrite<WriteHalf<SslStream<TcpStream>>, LdapCodec>),
}

impl fmt::Debug for LdapWriteTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapWriteTransport::Plain(_) => f
                .debug_struct("LdapWriteTransport")
                .field("type", &"plain")
                .finish(),
            LdapWriteTransport::Tls(_) => f
                .debug_struct("LdapWriteTransport")
                .field("type", &"tls")
                .finish(),
        }
    }
}

impl LdapWriteTransport {
    async fn send(&mut self, msg: LdapMsg) -> LdapResult<()> {
        match self {
            LdapWriteTransport::Plain(f) => f.send(msg).await.map_err(|e| {
                info!(?e, "transport error");
                LdapError::TransportWriteError
            }),
            LdapWriteTransport::Tls(f) => f.send(msg).await.map_err(|e| {
                info!(?e, "transport error");
                LdapError::TransportWriteError
            }),
        }
    }
}

impl LdapReadTransport {
    async fn next(&mut self) -> LdapResult<LdapMsg> {
        match self {
            LdapReadTransport::Plain(f) => f.next().await.transpose().map_err(|e| {
                info!(?e, "transport error");
                LdapError::TransportReadError
            })?,
            LdapReadTransport::Tls(f) => f.next().await.transpose().map_err(|e| {
                info!(?e, "transport error");
                LdapError::TransportReadError
            })?,
        }
        .ok_or_else(|| {
            info!("connection closed");
            LdapError::TransportReadError
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LdapEntry {
    pub dn: String,
    pub attrs: BTreeMap<String, BTreeSet<String>>,
}

impl LdapEntry {
    pub fn remove_ava_single(&mut self, attr: &str) -> Option<String> {
        if let Some(ava) = self.attrs.remove(attr) {
            if ava.len() == 1 {
                ava.into_iter().next()
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn remove_ava(&mut self, attr: &str) -> Option<BTreeSet<String>> {
        self.attrs.remove(attr)
    }
}

impl From<LdapSearchResultEntry> for LdapEntry {
    fn from(ent: LdapSearchResultEntry) -> Self {
        let LdapSearchResultEntry { dn, attributes } = ent;

        let attrs = attributes
            .into_iter()
            .map(|LdapPartialAttribute { atype, vals }| {
                let atype = atype.to_lowercase();

                let lower = atype == "objectclass";

                let va = vals
                    .into_iter()
                    .map(|bin| {
                        std::str::from_utf8(&bin)
                            .map(|s| {
                                if lower {
                                    s.to_lowercase()
                                } else {
                                    s.to_string()
                                }
                            })
                            .unwrap_or_else(|_| general_purpose::URL_SAFE.encode(&bin))
                    })
                    .collect();
                (atype, va)
            })
            .collect();

        LdapEntry { dn, attrs }
    }
}

pub struct LdapClientBuilder<'a> {
    url: &'a Url,
    timeout: Duration,
    cas: Vec<&'a Path>,
    verify: bool,
    /// The maximum LDAP packet size parsed during decoding.
    max_ber_size: Option<usize>,
}

impl<'a> LdapClientBuilder<'a> {
    pub fn new(url: &'a Url) -> Self {
        LdapClientBuilder {
            url,
            timeout: Duration::from_secs(30),
            cas: Vec::new(),
            verify: true,
            max_ber_size: None,
        }
    }

    pub fn set_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    pub fn add_tls_ca<T>(mut self, ca: &'a T) -> Self
    where
        T: AsRef<Path>,
    {
        self.cas.push(ca.as_ref());
        self
    }

    pub fn danger_accept_invalid_certs(self, accept_invalid_certs: bool) -> Self {
        Self {
            verify: !accept_invalid_certs,
            ..self
        }
    }

    /// Set the maximum size of a decoded message
    pub fn max_ber_size(self, max_ber_size: Option<usize>) -> Self {
        Self {
            max_ber_size,
            ..self
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn build(self) -> LdapResult<LdapClient> {
        let LdapClientBuilder {
            url,
            timeout,
            cas,
            verify,
            max_ber_size,
        } = self;

        info!(%url);
        info!(?timeout);

        // Check the scheme is ldap or ldaps
        // for now, no ldapi support.
        let need_tls = match url.scheme() {
            "ldapi" => return Err(LdapError::LdapiNotSupported),
            "cldap" => return Err(LdapError::UseCldapTool),
            "ldap" => false,
            "ldaps" => true,
            _ => return Err(LdapError::InvalidUrl),
        };

        info!(%need_tls);
        // get domain + port

        // Do we have query params? Can we use them?
        // https://ldap.com/ldap-urls/

        // resolve to a set of socket addrs.
        let addrs = url
            .socket_addrs(|| Some(if need_tls { 636 } else { 389 }))
            .map_err(|e| {
                info!(?e, "resolver error");
                LdapError::ResolverError
            })?;

        if addrs.is_empty() {
            return Err(LdapError::ResolverError);
        }

        addrs.iter().for_each(|address| info!(?address));

        let mut aiter = addrs.into_iter();

        // Try for each to open, with a timeout.
        let tcpstream = loop {
            if let Some(addr) = aiter.next() {
                let sleep = time::sleep(timeout);
                tokio::pin!(sleep);
                tokio::select! {
                    maybe_stream = TcpStream::connect(addr) => {
                        match maybe_stream {
                            Ok(t) => {
                                info!(?addr, "connection established");
                                break t;
                            }
                            Err(e) => {
                                info!(?addr, ?e, "error");
                                continue;
                            }
                        }
                    }
                    _ = &mut sleep => {
                        info!(?addr, "timeout");
                        continue;
                    }
                }
            } else {
                return Err(LdapError::ConnectError);
            }
        };

        // if they didn't set it in the builder then set it to the default
        let max_ber_size = max_ber_size.unwrap_or(ldap3_proto::DEFAULT_MAX_BER_SIZE);

        // If ldaps - start openssl
        let (write_transport, read_transport) = if need_tls {
            let mut tls_parms = SslConnector::builder(SslMethod::tls_client()).map_err(|e| {
                error!(?e, "openssl");
                LdapError::TlsError
            })?;

            let cert_store = tls_parms.cert_store_mut();
            for ca in cas.iter() {
                let mut file = File::open(ca).map_err(|e| {
                    error!(?e, "Unable to open {:?}", ca);
                    LdapError::FileIOError
                })?;

                let mut pem = Vec::new();
                file.read_to_end(&mut pem).map_err(|e| {
                    error!(?e, "Unable to read {:?}", ca);
                    LdapError::FileIOError
                })?;

                let ca_cert = X509::from_pem(pem.as_slice()).map_err(|e| {
                    error!(?e, "openssl");
                    LdapError::TlsError
                })?;

                cert_store
                    .add_cert(ca_cert)
                    .map(|()| {
                        info!("Added {:?} to cert store", ca);
                    })
                    .map_err(|e| {
                        error!(?e, "openssl");
                        LdapError::TlsError
                    })?;
            }
            if verify {
                tls_parms.set_verify(SslVerifyMode::PEER);
            } else {
                tls_parms.set_verify(SslVerifyMode::NONE);
            }
            let tls_parms = tls_parms.build();

            let mut tlsstream = Ssl::new(tls_parms.context())
                .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
                .map_err(|e| {
                    error!(?e, "openssl");
                    LdapError::TlsError
                })?;

            SslStream::connect(Pin::new(&mut tlsstream))
                .await
                .map_err(|e| {
                    error!(?e, "openssl");
                    LdapError::TlsError
                })?;

            info!("tls configured");

            let (r, w) = tokio::io::split(tlsstream);
            (
                LdapWriteTransport::Tls(FramedWrite::new(w, LdapCodec::default())),
                LdapReadTransport::Tls(FramedRead::new(r, LdapCodec::new(Some(max_ber_size)))),
            )
        } else {
            let (r, w) = tokio::io::split(tcpstream);
            (
                LdapWriteTransport::Plain(FramedWrite::new(w, LdapCodec::default())),
                LdapReadTransport::Plain(FramedRead::new(r, LdapCodec::new(Some(max_ber_size)))),
            )
        };

        let msg_counter = 1;

        // Good to go - return ok!
        Ok(LdapClient {
            read_transport,
            write_transport,
            msg_counter,
        })
    }
}

#[derive(Debug)]
pub struct LdapClient {
    read_transport: LdapReadTransport,
    write_transport: LdapWriteTransport,
    msg_counter: i32,
}

impl LdapClient {
    fn get_next_msgid(&mut self) -> i32 {
        let msgid = self.msg_counter;
        self.msg_counter += 1;
        msgid
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn bind(&mut self, dn: String, pw: String) -> LdapResult<()> {
        info!(%dn);
        let msgid = self.get_next_msgid();

        let msg = LdapMsg {
            msgid,
            op: LdapOp::BindRequest(LdapBindRequest {
                dn,
                cred: LdapBindCred::Simple(pw),
            }),
            ctrl: vec![],
        };

        self.write_transport.send(msg).await?;

        // Get the response
        self.read_transport
            .next()
            .await
            .and_then(|msg| match msg.op {
                LdapOp::BindResponse(res) => {
                    if res.res.code == LdapResultCode::Success {
                        info!("bind success");
                        Ok(())
                    } else {
                        info!(?res.res.code);
                        Err(LdapError::from(res.res.code))
                    }
                }
                op => {
                    trace!(?op);
                    Err(LdapError::InvalidProtocolState)
                }
            })
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn whoami(&mut self) -> LdapResult<Option<String>> {
        let msgid = self.get_next_msgid();

        let msg = LdapMsg {
            msgid,
            op: LdapOp::ExtendedRequest(Into::into(LdapWhoamiRequest {})),
            ctrl: vec![],
        };

        self.write_transport.send(msg).await?;

        self.read_transport
            .next()
            .await
            .and_then(|msg| match msg.op {
                LdapOp::ExtendedResponse(ler) => LdapWhoamiResponse::try_from(&ler)
                    .map_err(|_| LdapError::InvalidProtocolState)
                    .map(|res| res.dn),
                op => {
                    trace!(?op);
                    Err(LdapError::InvalidProtocolState)
                }
            })
    }
}

/// Doesn't test the actual *build* step because that requires a live LDAP server.
#[test]
fn test_ldapclient_builder() {
    let url = Url::parse("ldap://ldap.example.com:389").unwrap();
    let client = LdapClientBuilder::new(&url).max_ber_size(Some(1234567));
    assert_eq!(client.timeout, Duration::from_secs(30));
    let client = client.set_timeout(Duration::from_secs(60));
    assert_eq!(client.timeout, Duration::from_secs(60));
    assert_eq!(client.cas.len(), 0);
    assert_eq!(client.max_ber_size, Some(1234567));
    assert_eq!(client.verify, true);

    let ca_path = "test.pem".to_string();
    let client = client.add_tls_ca(&ca_path);
    assert_eq!(client.cas.len(), 1);

    let badssl_client = client.danger_accept_invalid_certs(true);
    assert_eq!(badssl_client.verify, false);
}
