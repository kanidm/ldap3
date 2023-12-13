use std::fmt;

use bytes::BytesMut;
use lber::{
    common::TagClass,
    structure::StructureTag,
    structures::{ASNTag, Boolean, Enumerated, Integer, OctetString, Sequence, Tag},
    universal::Types,
    Parser,
};
use uuid::Uuid;

use crate::{
    bytes_to_string,
    error::LdapProtoError,
    proto::{ber_bool_to_bool, ber_integer_to_i64, SyncRequestMode, SyncStateValue}, LdapResultCode,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq,Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapControl {
    SyncRequest {
        // Shouldn't this imply true?
        criticality: bool,
        mode: SyncRequestMode,
        cookie: Option<Vec<u8>>,
        reload_hint: bool,
    },
    SyncState {
        state: SyncStateValue,
        entry_uuid: Uuid,
        cookie: Option<Vec<u8>>,
    },
    SyncDone {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
    },
    AdDirsync {
        flags: i64,
        // Msdn and wireshark disagree on the name of this type.
        max_bytes: i64,
        cookie: Option<Vec<u8>>,
    },
    // https://www.ietf.org/rfc/rfc2696.txt
    SimplePagedResults {
        size: i64,
        cookie: Vec<u8>,
    },
    ManageDsaIT {
        criticality: bool,
    },
    //1.2.840.113556.1.4.473
    ServerSort {
        sort_requests: Vec<ServerSortRequet>,
    },

    ServerSortResult {
        sort_result: ServerSortResult,
    },
}

#[derive(Debug, Clone, PartialEq,Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct ServerSortResult {
    pub result_code: LdapResultCode,
    pub attribute_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct ServerSortRequet {
    pub attribute_name: String,
    pub ordering_rule: Option<String>,
    pub reverse_order: bool,
}

impl fmt::Debug for LdapControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapControl::SyncRequest {
                criticality,
                mode,
                cookie,
                reload_hint,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::SyncRequest")
                    .field("criticality", &criticality)
                    .field("mode", &mode)
                    .field("cookie", &d_cookie)
                    .field("reload_hint", &reload_hint)
                    .finish()
            }
            LdapControl::SyncState {
                state,
                entry_uuid,
                cookie,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::SyncState")
                    .field("state", &state)
                    .field("entry_uuid", &entry_uuid)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::SyncDone")
                    .field("refresh_deletes", &refresh_deletes)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::AdDirsync")
                    .field("flags", &flags)
                    .field("max_bytes", &max_bytes)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::SimplePagedResults { size, cookie } => {
                let d_cookie = bytes_to_string!(cookie);
                f.debug_struct("LdapControl::SimplePagedResults")
                    .field("size", &size)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::ManageDsaIT { criticality } => f
                .debug_struct("LdapControl::ManageDsaIT")
                .field("criticality", &criticality)
                .finish(),

            LdapControl::ServerSort { sort_requests } => f
                .debug_struct("LdapControl::ServerSort")
                .field("sort_requests", &sort_requests)
                .finish(),
            LdapControl::ServerSortResult { sort_result } => f
                .debug_struct("LdapControl::ServerSortResult")
                .field("sort_result", &sort_result)
                .finish(),
        }
    }
}

impl TryFrom<StructureTag> for LdapControl {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        let mut seq = value
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::ControlBer)?;

        // We destructure in reverse order due to how vec in rust
        // works.
        let (oid_tag, criticality_tag, value_tag) = match seq.len() {
            1 => {
                let v = None;
                let c = None;
                let o = seq.pop();
                (o, c, v)
            }
            2 => {
                let v = seq.pop();
                let c = None;
                let o = seq.pop();
                (o, c, v)
            }
            3 => {
                let v = seq.pop();
                let c = seq.pop();
                let o = seq.pop();
                (o, c, v)
            }
            _ => return Err(LdapProtoError::ControlSeqLen),
        };

        trace!(?oid_tag, ?criticality_tag, ?value_tag);

        // We need to know what the oid is first.
        let oid = oid_tag
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ControlBer)?;

        match oid.as_str() {
            "1.3.6.1.4.1.4203.1.9.1.1" => {
                // parse as sync req
                let criticality = criticality_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let mode = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Enumerated as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .and_then(|v| match v {
                        1 => Some(SyncRequestMode::RefreshOnly),
                        3 => Some(SyncRequestMode::RefreshAndPersist),
                        _ => None,
                    })
                    .ok_or(LdapProtoError::ControlSyncMode)?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                let reload_hint = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                Ok(LdapControl::SyncRequest {
                    criticality,
                    mode,
                    cookie,
                    reload_hint,
                })
            }
            "1.3.6.1.4.1.4203.1.9.1.2" => {
                // parse as sync state control

                //criticality is ignored.

                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let state = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Enumerated as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .and_then(|v| match v {
                        0 => Some(SyncStateValue::Present),
                        1 => Some(SyncStateValue::Add),
                        2 => Some(SyncStateValue::Modify),
                        3 => Some(SyncStateValue::Delete),
                        _ => None,
                    })
                    .ok_or(LdapProtoError::ControlSyncState)?;

                let entry_uuid = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)
                    .and_then(|v| {
                        Uuid::from_slice(&v).map_err(|_| LdapProtoError::ControlSyncUuid)
                    })?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                Ok(LdapControl::SyncState {
                    state,
                    entry_uuid,
                    cookie,
                })
            }
            "1.3.6.1.4.1.4203.1.9.1.3" => {
                // parse as sync done control
                // criticality is ignored.

                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                let refresh_deletes = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                Ok(LdapControl::SyncDone {
                    cookie,
                    refresh_deletes,
                })
            }
            "1.2.840.113556.1.4.841" => {
                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let flags = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Integer as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .ok_or(LdapProtoError::ControlAdDirsyncInteger)?;

                let max_bytes = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Integer as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .ok_or(LdapProtoError::ControlAdDirsyncInteger)?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                Ok(LdapControl::AdDirsync {
                    flags,
                    max_bytes,
                    cookie,
                })
            }
            "1.2.840.113556.1.4.319" => {
                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let size = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Integer as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .ok_or(LdapProtoError::ControlPagedInteger)?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlPagedCookie)?;

                Ok(LdapControl::SimplePagedResults { size, cookie })
            }
            "2.16.840.1.113730.3.4.2" => {
                // ManageDsaIT per https://www.rfc-editor.org/rfc/rfc3296

                let criticality = criticality_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                // Has no content.

                Ok(LdapControl::ManageDsaIT { criticality })
            }
            "1.2.840.113556.1.4.474" => {
                let value = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_, tag) = parser
                    .parse(&value)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut tags = tag
                    .match_class(TagClass::Universal)
                    .and_then(|t| t.match_id(Types::Sequence as u64))
                    .and_then(|t| t.expect_constructed())
                    .ok_or(LdapProtoError::ControlBer)?;

                let enum_tag = tags.pop().ok_or(LdapProtoError::ControlBer)?;

                let value = enum_tag
                    .match_class(TagClass::Universal)
                    .and_then(|t| t.match_id(Types::Enumerated as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let code = value.first().ok_or(LdapProtoError::ControlBer)?;

                Ok(LdapControl::ServerSortResult {
                    sort_result: ServerSortResult {
                        result_code: (*code as i64).try_into()?,
                        attribute_type: None, // TODO!
                    },
                })
            }
            oid => {
                warn!(%oid, "Unsupported control oid");
                Err(LdapProtoError::ControlUnknown)
            }
        }
    }
}

impl From<LdapControl> for Tag {
    fn from(value: LdapControl) -> Tag {
        let (oid, crit, inner_tag) = match value {
            LdapControl::SyncRequest {
                criticality,
                mode,
                cookie,
                reload_hint,
            } => {
                let inner: Vec<_> = vec![
                    Some(Tag::Enumerated(Enumerated {
                        inner: mode as i64,
                        ..Default::default()
                    })),
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    }),
                    if reload_hint {
                        Some(Tag::Boolean(Boolean {
                            inner: true,
                            ..Default::default()
                        }))
                    } else {
                        None
                    },
                ];

                (
                    "1.3.6.1.4.1.4203.1.9.1.1",
                    criticality,
                    Some(Tag::Sequence(Sequence {
                        inner: inner.into_iter().flatten().collect(),
                        ..Default::default()
                    })),
                )
            }
            LdapControl::SyncState {
                state,
                entry_uuid,
                cookie,
            } => {
                let inner: Vec<_> = vec![
                    Some(Tag::Enumerated(Enumerated {
                        inner: state as i64,
                        ..Default::default()
                    })),
                    Some(Tag::OctetString(OctetString {
                        inner: entry_uuid.as_bytes().to_vec(),
                        ..Default::default()
                    })),
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    }),
                ];

                (
                    "1.3.6.1.4.1.4203.1.9.1.2",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner: inner.into_iter().flatten().collect(),
                        ..Default::default()
                    })),
                )
            }
            LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            } => {
                let inner: Vec<_> = vec![
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    }),
                    if refresh_deletes {
                        Some(Tag::Boolean(Boolean {
                            inner: true,
                            ..Default::default()
                        }))
                    } else {
                        None
                    },
                ];

                (
                    "1.3.6.1.4.1.4203.1.9.1.3",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner: inner.into_iter().flatten().collect(),
                        ..Default::default()
                    })),
                )
            }
            LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            } => {
                let criticality = true;
                let inner: Vec<_> = vec![
                    Tag::Integer(Integer {
                        inner: flags,
                        ..Default::default()
                    }),
                    Tag::Integer(Integer {
                        inner: max_bytes,
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: cookie.unwrap_or_default(),
                        ..Default::default()
                    }),
                ];

                (
                    "1.2.840.113556.1.4.841",
                    criticality,
                    Some(Tag::Sequence(Sequence {
                        inner,
                        ..Default::default()
                    })),
                )
            }
            LdapControl::SimplePagedResults { size, cookie } => {
                let inner: Vec<_> = vec![
                    Tag::Integer(Integer {
                        inner: size,
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: cookie,
                        ..Default::default()
                    }),
                ];

                (
                    "1.2.840.113556.1.4.319",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner,
                        ..Default::default()
                    })),
                )
            }
            LdapControl::ManageDsaIT { criticality } => {
                ("2.16.840.1.113730.3.4.2", criticality, None)
            }
            LdapControl::ServerSort { sort_requests } => {
                let inner: Vec<_> = sort_requests
                    .into_iter()
                    .map(|sort_request| {
                        let mut inner = Vec::with_capacity(3);
                        inner.push(Tag::OctetString(OctetString {
                            inner: sort_request.attribute_name.into_bytes(),
                            ..Default::default()
                        }));
                        if let Some(ordering_rule) = sort_request.ordering_rule {
                            inner.push(Tag::OctetString(OctetString {
                                inner: ordering_rule.into_bytes(),
                                class: TagClass::Context,
                                id: 0,
                            }));
                        }
                        inner.push(Tag::Boolean(Boolean {
                            inner: sort_request.reverse_order,
                            class: TagClass::Context,
                            id: 1,
                        }));
                        Tag::Sequence(Sequence {
                            inner,
                            ..Default::default()
                        })
                    })
                    .collect();
                (
                    "1.2.840.113556.1.4.473",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner,
                        ..Default::default()
                    })),
                )
            }
            LdapControl::ServerSortResult { sort_result } => {
                let inner = vec![
                    Tag::Enumerated(Enumerated {
                        inner: sort_result.result_code as i64,
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: sort_result.attribute_type.unwrap_or_default().into_bytes(),
                        ..Default::default()
                    }),
                ];
                (
                    "1.2.840.113556.1.4.474",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner,
                        ..Default::default()
                    })),
                )
            }
        };

        let mut inner = Vec::with_capacity(3);

        inner.push(Tag::OctetString(OctetString {
            inner: Vec::from(oid),
            ..Default::default()
        }));
        if crit {
            inner.push(Tag::Boolean(Boolean {
                inner: true,
                ..Default::default()
            }));
        }

        if let Some(inner_tag) = inner_tag {
            let mut bytes = BytesMut::new();
            lber::write::encode_into(&mut bytes, inner_tag.into_structure())
                .expect("Failed to encode inner structure, this is a bug!");
            inner.push(Tag::OctetString(OctetString {
                inner: bytes.to_vec(),
                ..Default::default()
            }));
        }

        Tag::Sequence(Sequence {
            inner,
            ..Default::default()
        })
    }
}
