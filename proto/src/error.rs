use thiserror::Error;

#[derive(Error, Debug)]
pub enum LdapProtoError {
    #[error("The whoami response contains an invalid 'name' field")]
    WhoamiResponseName,

    #[error("Invalid oid in extended request")]
    PasswordModifyRequestOid,
    #[error("Password modify request value empty")]
    PasswordModifyRequestEmpty,
    #[error("Invalid BER in password modify request")]
    PasswordModifyRequestBer,
    #[error("Invalid value id tag in password modify request")]
    PasswordModifyRequestValueId,

    #[error("Missing password modify response name")]
    PasswordModifyResponseName,
    #[error("Password modify response value empty")]
    PasswordModifyResponseEmpty,
    #[error("Invalid BER in password modify response")]
    PasswordModifyResponseBer,

    #[error("The memory dump contains invalid BER")]
    OlMemDumpBer,

    #[error("The LDAP msg contains invalid BER")]
    LdapMsgBer,
    #[error("The LDAP msg has an invalid sequence length")]
    LdapMsgSeqLen,
    #[error("The LDAP msg has an invalid id")]
    LdapMsgId,
    #[error("The LDAP msg has no operation")]
    LdapMsgOp,

    #[error("Invalid operation tag")]
    LdapOpTag,
    #[error("Unknown operation type. This may be a bug in ldap3_proto.")]
    LdapOpUnknown,

    #[error("The request control is unknown. This may be a bug in ldap3_proto.")]
    ControlUnknown,

    #[error("Control contains invalid BER")]
    ControlBer,
    #[error("The control has an invalid sequence length")]
    ControlSeqLen,
    #[error("Invalid sync mode id requested in control")]
    ControlSyncMode,
    #[error("Invalid sync state id requested in control")]
    ControlSyncState,
    #[error("Invalid sync uuid in control")]
    ControlSyncUuid,
    #[error("Invalid integer in ad dirsync control")]
    ControlAdDirsyncInteger,
    #[error("Invalid integer in paged search control")]
    ControlPagedInteger,
    #[error("Missing cookie data in paged search control")]
    ControlPagedCookie,

    #[error("Invalid BER in bind credentials")]
    BindCredBer,
    #[error("Invalid value id in bind credentials")]
    BindCredId,

    #[error("Bind request version is not equal to 3. This is a serious client bug.")]
    BindRequestVersion,
    #[error("Invalid BER in bind request.")]
    BindRequestBer,

    #[error("Invalid BER in result.")]
    ResultBer,

    #[error("Invalid Tag in filter")]
    FilterTag,
    #[error("Invalid BER in filter")]
    FilterBer,

    #[error("Invalid BER in search")]
    SearchBer,

    #[error("Invalid BER in modify")]
    ModifyBer,

    #[error("Invalid BER in partial attribute")]
    PartialAttributeBer,

    #[error("Invalid BER in search result entry")]
    SearchResultEntryBer,

    #[error("Invalid BER in extended request")]
    ExtendedRequestBer,

    #[error("Intermediate response tag is invalid")]
    IntermediateResponseTag,
    #[error("Invalid intermediate response id")]
    IntermediateResponseId,
    #[error("Invalid BER in intermediate response")]
    IntermediateResponseBer,
    #[error("Invalid Sync UUID in intermediate response")]
    IntermediateResponseSyncUuid,

    #[error("Invalid modify type value")]
    ModifyTypeValue,
    #[error("Invalid search scope value")]
    SearchScopeValue,

    #[error("Invalid deref aliases value")]
    DerefAliasesValue,

    #[error("Invalid BER in modify request")]
    ModifyRequestBer,

    #[error("Invalid BER in add request")]
    AddRequestBer,

    #[error("Invalid BER in modify dn request")]
    ModifyDNRequestBer,

    #[error("Invalid BER in compare request")]
    CompareRequestBer,

    #[error("Invalid or unknown result code")]
    ResultCode,

    #[error("Invalid BER in delete request")]
    DelRequestBer,

    #[error("Invalid BER in abandon request")]
    AbandonRequestBer,
}
