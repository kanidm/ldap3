use crate::proto::*;
pub use crate::proto::{
    LdapFilter, LdapMsg, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
    LdapSearchScope,
};
use std::convert::TryFrom;

pub struct SearchRequest {
    pub msgid: i32,
    pub base: String,
    pub scope: LdapSearchScope,
    pub filter: LdapFilter,
    pub attrs: Vec<String>,
}

pub struct SimpleBindRequest {
    pub msgid: i32,
    pub dn: String,
    pub pw: String,
}

pub struct UnbindRequest;

pub struct WhoamiRequest {
    pub msgid: i32,
}

pub struct DisconnectionNotice;

pub enum ServerOps {
    Search(SearchRequest),
    SimpleBind(SimpleBindRequest),
    Unbind(UnbindRequest),
    Whoami(WhoamiRequest),
}

impl TryFrom<LdapMsg> for ServerOps {
    type Error = ();

    fn try_from(value: LdapMsg) -> Result<Self, Self::Error> {
        let LdapMsg { msgid, op, ctrl: _ } = value;
        match op {
            LdapOp::BindRequest(LdapBindRequest {
                dn,
                cred: LdapBindCred::Simple(pw),
            }) => Ok(ServerOps::SimpleBind(SimpleBindRequest { msgid, dn, pw })),
            LdapOp::UnbindRequest => Ok(ServerOps::Unbind(UnbindRequest)),
            LdapOp::SearchRequest(lsr) => {
                let LdapSearchRequest {
                    base,
                    scope,
                    aliases: _,
                    sizelimit: _,
                    timelimit: _,
                    typesonly: _,
                    filter,
                    attrs,
                } = lsr;
                Ok(ServerOps::Search(SearchRequest {
                    msgid,
                    base,
                    scope,
                    filter,
                    attrs,
                }))
            }
            LdapOp::ExtendedRequest(ler) => match ler.name.as_str() {
                "1.3.6.1.4.1.4203.1.11.3" => Ok(ServerOps::Whoami(WhoamiRequest { msgid })),
                _ => Err(()),
            },
            _ => Err(()),
        }
    }
}

impl DisconnectionNotice {
    pub fn gen(code: LdapResultCode, msg: &str) -> LdapMsg {
        // name 1.3.6.1.4.1.1466.20036
        // value == ""
        LdapMsg {
            msgid: 0,
            op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                res: LdapResult {
                    code,
                    matcheddn: "".to_string(),
                    message: msg.to_string(),
                    referral: Vec::new(),
                },
                name: Some("1.3.6.1.4.1.1466.20036".to_string()),
                value: None,
            }),
            ctrl: vec![],
        }
    }
}

impl SearchRequest {
    pub fn gen_result_entry(&self, entry: LdapSearchResultEntry) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::SearchResultEntry(entry),
            ctrl: vec![],
        }
    }

    pub fn gen_success(&self) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::SearchResultDone(LdapResult {
                code: LdapResultCode::Success,
                matcheddn: "".to_string(),
                message: "".to_string(),
                referral: vec![],
            }),
            ctrl: vec![],
        }
    }

    pub fn gen_operror(&self, msg: &str) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::SearchResultDone(LdapResult {
                code: LdapResultCode::OperationsError,
                matcheddn: "".to_string(),
                message: msg.to_string(),
                referral: vec![],
            }),
            ctrl: vec![],
        }
    }
}

impl SimpleBindRequest {
    pub fn gen_success(&self) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            }),
            ctrl: vec![],
        }
    }

    pub fn gen_invalid_cred(&self) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::InvalidCredentials,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            }),
            ctrl: vec![],
        }
    }

    pub fn gen_operror(&self, msg: &str) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::OperationsError,
                    matcheddn: "".to_string(),
                    message: msg.to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            }),
            ctrl: vec![],
        }
    }
}

impl WhoamiRequest {
    pub fn gen_success(&self, authzid: &str) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                name: None,
                value: Some(Vec::from(authzid)),
            }),
            ctrl: vec![],
        }
    }

    pub fn gen_operror(&self, msg: &str) -> LdapMsg {
        LdapMsg {
            msgid: self.msgid,
            op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                res: LdapResult {
                    code: LdapResultCode::OperationsError,
                    matcheddn: "".to_string(),
                    message: msg.to_string(),
                    referral: Vec::new(),
                },
                name: None,
                value: None,
            }),
            ctrl: vec![],
        }
    }
}
