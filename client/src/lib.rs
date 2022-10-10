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
use std::collections::{BTreeMap, BTreeSet};
use tokio_openssl::SslStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use std::fmt;
use url::Url;
use uuid::Uuid;

pub use ldap3_proto::filter;
pub use ldap3_proto::proto;

mod addirsync;
mod search;
mod syncrepl;

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

    UnavailableCriticalExtension = 12,
    InvalidCredentials = 49,
    InsufficentAccessRights = 50,
    EsyncRefreshRequired = 4096,
}

impl From<LdapResultCode> for LdapError {
    fn from(code: LdapResultCode) -> Self {
        match code {
            LdapResultCode::InvalidCredentials => LdapError::InvalidCredentials,
            LdapResultCode::InsufficentAccessRights => LdapError::InsufficentAccessRights,
            LdapResultCode::EsyncRefreshRequired => LdapError::EsyncRefreshRequired,
            LdapResultCode::UnavailableCriticalExtension => LdapError::UnavailableCriticalExtension,
            err => {
                trace!(?err);
                unimplemented!()
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
            LdapError::TransportReadError => {
                write!(f, "An error occured reading from the transport")
            }
            LdapError::TransportWriteError => {
                write!(f, "An error occured writing to the transport")
            }
            LdapError::UnavailableCriticalExtension => write!(f, "An extension marked as critical was not available"),
            LdapError::InvalidCredentials => write!(f, "Invalid DN or Password"),
            LdapError::InsufficentAccessRights => write!(f, "Insufficent Access"),
            LdapError::EsyncRefreshRequired => write!(f, "An initial content sync is required. The current cookie should be considered invalid."),
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

#[derive(Debug)]
pub struct LdapEntry {
    pub dn: String,
    pub attrs: BTreeMap<String, BTreeSet<String>>,
}

impl From<LdapSearchResultEntry> for LdapEntry {
    fn from(ent: LdapSearchResultEntry) -> Self {
        let LdapSearchResultEntry { dn, attributes } = ent;

        let attrs = attributes
            .into_iter()
            .map(|LdapPartialAttribute { atype, vals }| {
                let va = vals
                    .into_iter()
                    .map(|bin| {
                        std::str::from_utf8(&bin)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|_| {
                                base64::encode_config(&bin, base64::STANDARD_NO_PAD)
                            })
                    })
                    .collect();
                (atype, va)
            })
            .collect();

        LdapEntry { dn, attrs }
    }
}

#[derive(Debug)]
pub struct LdapClient {
    read_transport: LdapReadTransport,
    write_transport: LdapWriteTransport,
    msg_counter: i32,
}

impl LdapClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn new(url: &Url, timeout: Duration) -> LdapResult<Self> {
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

        // If ldaps - start openssl
        let (write_transport, read_transport) = if need_tls {
            let mut tls_parms = SslConnector::builder(SslMethod::tls_client()).map_err(|e| {
                info!(?e, "openssl");
                LdapError::TlsError
            })?;
            tls_parms.set_verify(SslVerifyMode::NONE);
            let tls_parms = tls_parms.build();

            let mut tlsstream = Ssl::new(tls_parms.context())
                .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
                .map_err(|e| {
                    info!(?e, "openssl");
                    LdapError::TlsError
                })?;

            let _ = SslStream::connect(Pin::new(&mut tlsstream))
                .await
                .map_err(|e| {
                    info!(?e, "openssl");
                    LdapError::TlsError
                })?;

            info!("tls configured");
            let (r, w) = tokio::io::split(tlsstream);
            (
                LdapWriteTransport::Tls(FramedWrite::new(w, LdapCodec)),
                LdapReadTransport::Tls(FramedRead::new(r, LdapCodec)),
            )
        } else {
            let (r, w) = tokio::io::split(tcpstream);
            (
                LdapWriteTransport::Plain(FramedWrite::new(w, LdapCodec)),
                LdapReadTransport::Plain(FramedRead::new(r, LdapCodec)),
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
