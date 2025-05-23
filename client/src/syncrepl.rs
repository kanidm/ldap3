use crate::LdapClient;
use crate::*;
use ldap3_proto::control::LdapControl;
use serde::{Deserialize, Serialize};
use serde_with::{base64, formats, serde_as};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum LdapSyncStateValue {
    Present,
    Add,
    Modify,
    Delete,
}

impl From<SyncStateValue> for LdapSyncStateValue {
    fn from(v: SyncStateValue) -> LdapSyncStateValue {
        match v {
            SyncStateValue::Present => LdapSyncStateValue::Present,
            SyncStateValue::Add => LdapSyncStateValue::Add,
            SyncStateValue::Modify => LdapSyncStateValue::Modify,
            SyncStateValue::Delete => LdapSyncStateValue::Delete,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LdapSyncReplEntry {
    pub entry_uuid: Uuid,
    pub state: LdapSyncStateValue,
    pub entry: LdapEntry,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub enum LdapSyncRepl {
    Success {
        #[serde_as(as = "Option<base64::Base64<base64::UrlSafe, formats::Unpadded>>")]
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
        entries: Vec<LdapSyncReplEntry>,
        delete_uuids: Option<Vec<Uuid>>,
        present_uuids: Option<Vec<Uuid>>,
    },
    RefreshRequired,
}

impl LdapClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn syncrepl<S: Into<String>>(
        &mut self,
        basedn: S,
        filter: LdapFilter,
        cookie: Option<Vec<u8>>,
        mode: SyncRequestMode,
    ) -> crate::LdapResult<LdapSyncRepl> {
        let msgid = self.get_next_msgid();

        let msg = LdapMsg {
            msgid,
            op: LdapOp::SearchRequest(LdapSearchRequest {
                base: basedn.into(),
                scope: LdapSearchScope::Subtree,
                aliases: LdapDerefAliases::Never,
                sizelimit: 0,
                timelimit: 0,
                typesonly: false,
                filter,
                attrs: vec!["*".to_string(), "+".to_string()],
            }),
            ctrl: vec![LdapControl::SyncRequest {
                criticality: true,
                mode,
                cookie,
                reload_hint: false,
            }],
        };

        self.write_transport.send(msg).await?;

        let mut entries = Vec::new();
        let mut delete_uuids: Option<Vec<_>> = None;
        let mut present_uuids: Option<Vec<_>> = None;

        loop {
            let mut msg = self.read_transport.next().await?;

            match msg.op {
                // Happy cases here
                LdapOp::SearchResultDone(proto::LdapResult {
                    code: LdapResultCode::Success,
                    message: _,
                    matcheddn: _,
                    referral: _,
                }) => {
                    trace!("SearchResultDone");
                    if let Some(LdapControl::SyncDone {
                        cookie,
                        refresh_deletes,
                    }) = msg.ctrl.pop()
                    {
                        break Ok(LdapSyncRepl::Success {
                            cookie,
                            refresh_deletes,
                            entries,
                            delete_uuids,
                            present_uuids,
                        });
                    } else {
                        error!("Invalid Sync Control encountered");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
                // Indicate to the client they need to refresh
                LdapOp::SearchResultDone(proto::LdapResult {
                    code: LdapResultCode::EsyncRefreshRequired,
                    message,
                    matcheddn: _,
                    referral: _,
                }) => {
                    error!(%message);
                    break Ok(LdapSyncRepl::RefreshRequired);
                }
                LdapOp::IntermediateResponse(LdapIntermediateResponse::SyncInfoIdSet {
                    cookie: _,
                    refresh_deletes,
                    syncuuids,
                }) => {
                    trace!(?refresh_deletes, ?syncuuids);
                    //  Multiple empty entries with a Sync State Control of state delete
                    // SHOULD be coalesced into one or more Sync Info Messages of syncIdSet
                    // value with refreshDeletes set to TRUE.  syncUUIDs contain a set of
                    // UUIDs of the entries and references that have been deleted from the
                    // content since the last Sync Operation.  syncUUIDs may be empty.  The
                    // Sync Info Message of syncIdSet may contain a cookie to represent the
                    // state of the content after performing the synchronization of the
                    // entries in the set.
                    if refresh_deletes {
                        let d_uuids = delete_uuids.get_or_insert_with(Vec::default);
                        d_uuids.extend(syncuuids.into_iter());
                    } else {
                        let p_uuids = present_uuids.get_or_insert_with(Vec::default);
                        p_uuids.extend(syncuuids.into_iter());
                    }
                }
                LdapOp::IntermediateResponse(LdapIntermediateResponse::SyncInfoRefreshDelete {
                    cookie: _,
                    done: false,
                }) => {
                    // These are no-ops that are skipped for our purposes
                    // They are intended to deliniate the separate phases, but we actually don't
                    // care until we get the search result done.
                    let _d_uuids = delete_uuids.get_or_insert_with(Vec::default);
                }
                LdapOp::IntermediateResponse(
                    LdapIntermediateResponse::SyncInfoRefreshPresent {
                        cookie: _,
                        done: false,
                    },
                ) => {
                    // These are no-ops that are skipped for our purposes
                    // They are intended to deliniate the separate phases, but we actually don't
                    // care until we get the search result done.
                    let _p_uuids = present_uuids.get_or_insert_with(Vec::default);
                }
                LdapOp::SearchResultEntry(entry) => {
                    if let Some(LdapControl::SyncState {
                        state,
                        entry_uuid,
                        cookie,
                    }) = msg.ctrl.pop()
                    {
                        if let Some(cookie) = cookie {
                            trace!(?cookie);
                        }
                        entries.push(LdapSyncReplEntry {
                            entry_uuid,
                            state: state.into(),
                            entry: entry.into(),
                        })
                    } else {
                        error!("Invalid Sync Control encountered");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
                LdapOp::SearchResultReference(_search_reference) => {
                    // pass
                }
                // Error cases below
                LdapOp::SearchResultDone(proto::LdapResult {
                    code,
                    message,
                    matcheddn: _,
                    referral: _,
                }) => {
                    error!(%message);
                    break Err(LdapError::from(code));
                }
                op => {
                    trace!(?op, "<<<<==== ");
                    break Err(LdapError::InvalidProtocolState);
                }
            };
        }
    }
}
