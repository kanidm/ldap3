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

use base64::{engine::general_purpose, Engine as _};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use ldap3_proto::proto::*;
use ldap3_proto::LdapCodec;
use rustls_platform_verifier::ConfigVerifierExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time;

use tokio_rustls::{
    client::TlsStream,
    rustls::client::{danger::*, ClientConfig},
    rustls::pki_types::{CertificateDer, ServerName, UnixTime},
    rustls::Error as RustlsError,
    rustls::{DigitallySignedStruct, SignatureScheme},
    TlsConnector,
};

use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, info, trace, warn};
use url::{Host, Url};
use uuid::Uuid;

pub use ldap3_proto::filter;
pub use ldap3_proto::proto;
pub use search::LdapSearchResult;
pub use syncrepl::{LdapSyncRepl, LdapSyncReplEntry, LdapSyncStateValue};
pub use tokio::time::Duration;

mod addirsync;
mod search;
mod syncrepl;

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
                write!(f, "An error occurred while accessing a file")
            }
            LdapError::TransportReadError => {
                write!(f, "An error occurred reading from the transport")
            }
            LdapError::TransportWriteError => {
                write!(f, "An error occurred writing to the transport")
            }
            LdapError::UnavailableCriticalExtension => write!(f, "An extension marked as critical was not available"),
            LdapError::InvalidCredentials => write!(f, "Invalid DN or Password"),
            LdapError::InsufficentAccessRights => write!(f, "Insufficient Access"),
            LdapError::UnwillingToPerform => write!(f, "Too many failures, server is unwilling to perform the operation."),
            LdapError::EsyncRefreshRequired => write!(f, "An initial content sync is required. The current cookie should be considered invalid."),
            LdapError::NotImplemented => write!(f, "An error occurred, but we haven't implemented code to handle this error yet.")
        }
    }
}

pub type LdapResult<T> = Result<T, LdapError>;

enum LdapReadTransport {
    Plain(FramedRead<ReadHalf<TcpStream>, LdapCodec>),
    Tls(FramedRead<ReadHalf<TlsStream<TcpStream>>, LdapCodec>),
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
    Tls(FramedWrite<WriteHalf<TlsStream<TcpStream>>, LdapCodec>),
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
    pub fn get_ava_single(&self, attr: &str) -> Option<&str> {
        if let Some(ava) = self.attrs.get(attr) {
            if ava.len() == 1 {
                ava.iter().next().map(String::as_ref)
            } else {
                None
            }
        } else {
            None
        }
    }

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
    /// The maximum LDAP packet size parsed during decoding.
    max_ber_size: Option<usize>,
    rustls_client: Option<Arc<ClientConfig>>,
}

impl<'a> LdapClientBuilder<'a> {
    pub fn new(url: &'a Url) -> Self {
        Self {
            url,
            timeout: Duration::from_secs(30),
            max_ber_size: None,
            rustls_client: None,
        }
    }

    pub fn set_tls_config(&mut self, config: Option<Arc<ClientConfig>>) {
        self.rustls_client = config
    }

    /// set the rustls [`ClientConfig`] used to handle ldaps connections
    ///
    /// if not set uses the platform verifier
    pub fn with_tls_config(mut self, config: ClientConfig) -> Self {
        self.set_tls_config(Some(Arc::new(config)));
        self
    }

    /// set rustls [`ClientConfig`] to one that does not verify the server certificate
    pub fn danger_accept_invalid_certs(self) -> Self {
        warn!("⚠️ CERTIFICATE VERIFICATION IS DISABLED. THIS IS DANGEROUS!!!!");
        let yolo_cert_validator = Arc::new(YoloCertValidator);

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(yolo_cert_validator)
            .with_no_client_auth();
        self.with_tls_config(client_config)
    }

    pub fn set_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
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
            max_ber_size,
            rustls_client,
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

        // If they didn't set it in the builder then set it to the default
        let max_ber_size = max_ber_size.unwrap_or(ldap3_proto::DEFAULT_MAX_BER_SIZE);

        // If ldaps - start rustls
        let (write_transport, read_transport) = if need_tls {
            let tls_client_config = if let Some(client_config) = rustls_client {
                client_config
            } else {
                Arc::new(ClientConfig::with_platform_verifier().map_err(|e| {
                    error!(?e, "rustls");
                    LdapError::TlsError
                })?)
            };

            let tls_connector = TlsConnector::from(tls_client_config);

            let server_name = match url.host() {
                Some(Host::Domain(name)) => {
                    ServerName::try_from(name.to_owned()).map_err(|err| {
                        error!(?err, "server name invalid");
                        LdapError::TlsError
                    })?
                }
                Some(Host::Ipv4(addr)) => ServerName::from(addr),
                Some(Host::Ipv6(addr)) => ServerName::from(addr),
                None => {
                    error!("url invalid");
                    return Err(LdapError::TlsError);
                }
            };

            let tlsstream = tls_connector
                .connect(
                    server_name,
                    // Pin::new(&mut tcpstream)
                    tcpstream,
                )
                .await
                .map_err(|e| {
                    error!(?e, "rustls");
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
    pub async fn bind<S: Into<String>>(&mut self, dn: S, pw: S) -> LdapResult<()> {
        let dn = dn.into();
        info!(%dn);
        let msgid = self.get_next_msgid();

        let msg = LdapMsg {
            msgid,
            op: LdapOp::BindRequest(LdapBindRequest {
                dn,
                cred: LdapBindCred::Simple(pw.into()),
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

#[derive(Debug)]
/// This should never be used for anything but testing, as it does no verification!
struct YoloCertValidator;

impl ServerCertVerifier for YoloCertValidator {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Yolo.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
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
    assert_eq!(client.max_ber_size, Some(1234567));
    assert!(client.rustls_client.is_none());
}
