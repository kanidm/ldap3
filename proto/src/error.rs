use thiserror::Error;

#[derive(Error, Debug)]
pub enum LdapProtoError {
    #[error("The whoami response contains an invalid 'name' field")]
    WhoamiResponseName,

    #[error("")]
    PasswordModifyRequestOid,
    #[error("")]
    PasswordModifyRequestEmpty,
    #[error("")]
    PasswordModifyRequestBer,
    #[error("")]
    PasswordModifyRequestValueId,

    #[error("")]
    PasswordModifyResponseName,
    #[error("")]
    PasswordModifyResponseEmpty,
    #[error("")]
    PasswordModifyResponseBer,

    #[error("The memory dump contains invalid BER")]
    OlMemDumpBer,

    #[error("")]
    LdapMsgBer,
    #[error("")]
    LdapMsgSeqLen,
    #[error("")]
    LdapMsgId,
    #[error("")]
    LdapMsgOp,

    #[error("")]
    LdapOpTag,
    #[error("")]
    LdapOpUnknown,

    #[error("")]
    ControlUnknown,

    #[error("")]
    ControlBer,
    #[error("")]
    ControlSeqLen,
    #[error("")]
    ControlSyncMode,
    #[error("")]
    ControlSyncState,
    #[error("")]
    ControlSyncUuid,
    #[error("")]
    ControlAdDirsyncInteger,
    #[error("")]
    ControlPagedInteger,
    #[error("")]
    ControlPagedUtf8,

    #[error("")]
    BindCredBer,
    #[error("")]
    BindCredId,

    #[error("")]
    BindRequestVersion,
    #[error("")]
    BindRequestBer,

    #[error("")]
    ResultBer,

    #[error("")]
    FilterTag,
    #[error("")]
    FilterBer,

    #[error("")]
    SearchBer,

    #[error("")]
    ModifyBer,

    #[error("")]
    PartialAttributeBer,

    #[error("")]
    SearchResultEntryBer,

    #[error("")]
    ExtendedRequestBer,

    #[error("")]
    IntermediateResponseTag,
    #[error("")]
    IntermediateResponseId,
    #[error("")]
    IntermediateResponseBer,
    #[error("")]
    IntermediateResponseSyncUuid,

    #[error("")]
    ModifyTypeValue,
    #[error("")]
    SearchScopeValue,

    #[error("")]
    DerefAliasesValue,

    #[error("")]
    ModifyRequestBer,

    #[error("")]
    AddRequestBer,

    #[error("")]
    ModifyDNRequestBer,

    #[error("")]
    CompareRequestBer,

    #[error("")]
    ResultCode,

    #[error("")]
    DelRequestBer,

    #[error("")]
    AbandonRequestBer,
}
