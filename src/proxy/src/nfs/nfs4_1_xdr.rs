// GENERATED CODE
//
// Originally Generated from src/nfs/nfs_4_1_prot.x by xdrgen.
// Modifications are done to implement optimizations for memory copy for opaque data payloads.
//
#![allow(warnings)]
#![allow(clippy)]
#![allow(unknown_lints)]
#![allow(deprecated)]
#![allow(invalid_value)]
#![allow(unused)]

use bytes::Bytes;

pub const ACCESS4_DELETE: i64 = 16i64;

pub const ACCESS4_EXECUTE: i64 = 32i64;

pub const ACCESS4_EXTEND: i64 = 8i64;

pub const ACCESS4_LOOKUP: i64 = 2i64;

pub const ACCESS4_MODIFY: i64 = 4i64;

pub const ACCESS4_READ: i64 = 1i64;

pub const ACCESS4_XALIST: i64 = 256i64;

pub const ACCESS4_XAREAD: i64 = 64i64;

pub const ACCESS4_XAWRITE: i64 = 128i64;

pub const ACE4_ACCESS_ALLOWED_ACE_TYPE: i64 = 0i64;

pub const ACE4_ACCESS_DENIED_ACE_TYPE: i64 = 1i64;

pub const ACE4_ADD_FILE: i64 = 2i64;

pub const ACE4_ADD_SUBDIRECTORY: i64 = 4i64;

pub const ACE4_APPEND_DATA: i64 = 4i64;

pub const ACE4_DELETE: i64 = 16384i64;

pub const ACE4_DELETE_CHILD: i64 = 64i64;

pub const ACE4_DIRECTORY_INHERIT_ACE: i64 = 2i64;

pub const ACE4_EXECUTE: i64 = 32i64;

pub const ACE4_FAILED_ACCESS_ACE_FLAG: i64 = 32i64;

pub const ACE4_FILE_INHERIT_ACE: i64 = 1i64;

pub const ACE4_GENERIC_EXECUTE: i64 = 262176i64;

pub const ACE4_GENERIC_READ: i64 = 262145i64;

pub const ACE4_GENERIC_WRITE: i64 = 262161i64;

pub const ACE4_IDENTIFIER_GROUP: i64 = 64i64;

pub const ACE4_INHERITED_ACE: i64 = 128i64;

pub const ACE4_INHERIT_ONLY_ACE: i64 = 8i64;

pub const ACE4_LIST_DIRECTORY: i64 = 1i64;

pub const ACE4_NO_PROPAGATE_INHERIT_ACE: i64 = 4i64;

pub const ACE4_READ_ACL: i64 = 32768i64;

pub const ACE4_READ_ATTRIBUTES: i64 = 128i64;

pub const ACE4_READ_DATA: i64 = 1i64;

pub const ACE4_READ_NAMED_ATTRS: i64 = 8i64;

pub const ACE4_SUCCESSFUL_ACCESS_ACE_FLAG: i64 = 16i64;

pub const ACE4_SYNCHRONIZE: i64 = 262144i64;

pub const ACE4_SYSTEM_ALARM_ACE_TYPE: i64 = 3i64;

pub const ACE4_SYSTEM_AUDIT_ACE_TYPE: i64 = 2i64;

pub const ACE4_WRITE_ACL: i64 = 65536i64;

pub const ACE4_WRITE_ATTRIBUTES: i64 = 256i64;

pub const ACE4_WRITE_DATA: i64 = 2i64;

pub const ACE4_WRITE_NAMED_ATTRS: i64 = 16i64;

pub const ACE4_WRITE_OWNER: i64 = 131072i64;

pub const ACE4_WRITE_RETENTION: i64 = 512i64;

pub const ACE4_WRITE_RETENTION_HOLD: i64 = 1024i64;

pub const ACL4_AUTO_INHERIT: i64 = 1i64;

pub const ACL4_DEFAULTED: i64 = 4i64;

pub const ACL4_PROTECTED: i64 = 2i64;

pub const ACL4_SUPPORT_ALARM_ACL: i64 = 8i64;

pub const ACL4_SUPPORT_ALLOW_ACL: i64 = 1i64;

pub const ACL4_SUPPORT_AUDIT_ACL: i64 = 4i64;

pub const ACL4_SUPPORT_DENY_ACL: i64 = 2i64;

pub const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: i64 = 2i64;

pub const CREATE_SESSION4_FLAG_CONN_RDMA: i64 = 4i64;

pub const CREATE_SESSION4_FLAG_PERSIST: i64 = 1i64;

pub const EXCHGID4_FLAG_BIND_PRINC_STATEID: i64 = 256i64;

pub const EXCHGID4_FLAG_CONFIRMED_R: i64 = 2147483648i64;

pub const EXCHGID4_FLAG_MASK_PNFS: i64 = 12582912i64;

pub const EXCHGID4_FLAG_SUPP_MOVED_MIGR: i64 = 2i64;

pub const EXCHGID4_FLAG_SUPP_MOVED_REFER: i64 = 1i64;

pub const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: i64 = 1073741824i64;

pub const EXCHGID4_FLAG_USE_NON_PNFS: i64 = 65536i64;

pub const EXCHGID4_FLAG_USE_PNFS_DS: i64 = 262144i64;

pub const EXCHGID4_FLAG_USE_PNFS_MDS: i64 = 131072i64;

pub const FATTR4_ACL: i64 = 12i64;

pub const FATTR4_ACLSUPPORT: i64 = 13i64;

pub const FATTR4_ARCHIVE: i64 = 14i64;

pub const FATTR4_CANSETTIME: i64 = 15i64;

pub const FATTR4_CASE_INSENSITIVE: i64 = 16i64;

pub const FATTR4_CASE_PRESERVING: i64 = 17i64;

pub const FATTR4_CHANGE: i64 = 3i64;

pub const FATTR4_CHANGE_POLICY: i64 = 60i64;

pub const FATTR4_CHOWN_RESTRICTED: i64 = 18i64;

pub const FATTR4_DACL: i64 = 58i64;

pub const FATTR4_DIRENT_NOTIF_DELAY: i64 = 57i64;

pub const FATTR4_DIR_NOTIF_DELAY: i64 = 56i64;

pub const FATTR4_FH_EXPIRE_TYPE: i64 = 2i64;

pub const FATTR4_FILEHANDLE: i64 = 19i64;

pub const FATTR4_FILEID: i64 = 20i64;

pub const FATTR4_FILES_AVAIL: i64 = 21i64;

pub const FATTR4_FILES_FREE: i64 = 22i64;

pub const FATTR4_FILES_TOTAL: i64 = 23i64;

pub const FATTR4_FSID: i64 = 8i64;

pub const FATTR4_FS_CHARSET_CAP: i64 = 76i64;

pub const FATTR4_FS_LAYOUT_TYPE: i64 = 62i64;

pub const FATTR4_FS_LOCATIONS: i64 = 24i64;

pub const FATTR4_FS_LOCATIONS_INFO: i64 = 67i64;

pub const FATTR4_FS_STATUS: i64 = 61i64;

pub const FATTR4_HIDDEN: i64 = 25i64;

pub const FATTR4_HOMOGENEOUS: i64 = 26i64;

pub const FATTR4_LAYOUT_ALIGNMENT: i64 = 66i64;

pub const FATTR4_LAYOUT_BLKSIZE: i64 = 65i64;

pub const FATTR4_LAYOUT_HINT: i64 = 63i64;

pub const FATTR4_LAYOUT_TYPE: i64 = 64i64;

pub const FATTR4_LEASE_TIME: i64 = 10i64;

pub const FATTR4_LINK_SUPPORT: i64 = 5i64;

pub const FATTR4_MAXFILESIZE: i64 = 27i64;

pub const FATTR4_MAXLINK: i64 = 28i64;

pub const FATTR4_MAXNAME: i64 = 29i64;

pub const FATTR4_MAXREAD: i64 = 30i64;

pub const FATTR4_MAXWRITE: i64 = 31i64;

pub const FATTR4_MDSTHRESHOLD: i64 = 68i64;

pub const FATTR4_MIMETYPE: i64 = 32i64;

pub const FATTR4_MODE: i64 = 33i64;

pub const FATTR4_MODE_SET_MASKED: i64 = 74i64;

pub const FATTR4_MOUNTED_ON_FILEID: i64 = 55i64;

pub const FATTR4_NAMED_ATTR: i64 = 7i64;

pub const FATTR4_NO_TRUNC: i64 = 34i64;

pub const FATTR4_NUMLINKS: i64 = 35i64;

pub const FATTR4_OWNER: i64 = 36i64;

pub const FATTR4_OWNER_GROUP: i64 = 37i64;

pub const FATTR4_QUOTA_AVAIL_HARD: i64 = 38i64;

pub const FATTR4_QUOTA_AVAIL_SOFT: i64 = 39i64;

pub const FATTR4_QUOTA_USED: i64 = 40i64;

pub const FATTR4_RAWDEV: i64 = 41i64;

pub const FATTR4_RDATTR_ERROR: i64 = 11i64;

pub const FATTR4_RETENTEVT_GET: i64 = 71i64;

pub const FATTR4_RETENTEVT_SET: i64 = 72i64;

pub const FATTR4_RETENTION_GET: i64 = 69i64;

pub const FATTR4_RETENTION_HOLD: i64 = 73i64;

pub const FATTR4_RETENTION_SET: i64 = 70i64;

pub const FATTR4_SACL: i64 = 59i64;

pub const FATTR4_SIZE: i64 = 4i64;

pub const FATTR4_SPACE_AVAIL: i64 = 42i64;

pub const FATTR4_SPACE_FREE: i64 = 43i64;

pub const FATTR4_SPACE_TOTAL: i64 = 44i64;

pub const FATTR4_SPACE_USED: i64 = 45i64;

pub const FATTR4_SUPPATTR_EXCLCREAT: i64 = 75i64;

pub const FATTR4_SUPPORTED_ATTRS: i64 = 0i64;

pub const FATTR4_SYMLINK_SUPPORT: i64 = 6i64;

pub const FATTR4_SYSTEM: i64 = 46i64;

pub const FATTR4_TIME_ACCESS: i64 = 47i64;

pub const FATTR4_TIME_ACCESS_SET: i64 = 48i64;

pub const FATTR4_TIME_BACKUP: i64 = 49i64;

pub const FATTR4_TIME_CREATE: i64 = 50i64;

pub const FATTR4_TIME_DELTA: i64 = 51i64;

pub const FATTR4_TIME_METADATA: i64 = 52i64;

pub const FATTR4_TIME_MODIFY: i64 = 53i64;

pub const FATTR4_TIME_MODIFY_SET: i64 = 54i64;

pub const FATTR4_TYPE: i64 = 1i64;

pub const FATTR4_UNIQUE_HANDLES: i64 = 9i64;

pub const FATTR4_XATTR_SUPPORT: i64 = 82i64;

pub const FH4_NOEXPIRE_WITH_OPEN: i64 = 1i64;

pub const FH4_PERSISTENT: i64 = 0i64;

pub const FH4_VOLATILE_ANY: i64 = 2i64;

pub const FH4_VOL_MIGRATION: i64 = 4i64;

pub const FH4_VOL_RENAME: i64 = 8i64;

pub const FSCHARSET_CAP4_ALLOWS_ONLY_UTF8: i64 = 2i64;

pub const FSCHARSET_CAP4_CONTAINS_NON_UTF8: i64 = 1i64;

pub const FSLI4BX_CLCHANGE: i64 = 6i64;

pub const FSLI4BX_CLFILEID: i64 = 4i64;

pub const FSLI4BX_CLHANDLE: i64 = 3i64;

pub const FSLI4BX_CLREADDIR: i64 = 7i64;

pub const FSLI4BX_CLSIMUL: i64 = 2i64;

pub const FSLI4BX_CLWRITEVER: i64 = 5i64;

pub const FSLI4BX_GFLAGS: i64 = 0i64;

pub const FSLI4BX_READORDER: i64 = 10i64;

pub const FSLI4BX_READRANK: i64 = 8i64;

pub const FSLI4BX_TFLAGS: i64 = 1i64;

pub const FSLI4BX_WRITEORDER: i64 = 11i64;

pub const FSLI4BX_WRITERANK: i64 = 9i64;

pub const FSLI4GF_ABSENT: i64 = 4i64;

pub const FSLI4GF_CUR_REQ: i64 = 2i64;

pub const FSLI4GF_GOING: i64 = 8i64;

pub const FSLI4GF_SPLIT: i64 = 16i64;

pub const FSLI4GF_WRITABLE: i64 = 1i64;

pub const FSLI4IF_VAR_SUB: i64 = 1i64;

pub const FSLI4TF_RDMA: i64 = 1i64;

pub const MODE4_RGRP: i64 = 32i64;

pub const MODE4_ROTH: i64 = 4i64;

pub const MODE4_RUSR: i64 = 256i64;

pub const MODE4_SGID: i64 = 1024i64;

pub const MODE4_SUID: i64 = 2048i64;

pub const MODE4_SVTX: i64 = 512i64;

pub const MODE4_WGRP: i64 = 16i64;

pub const MODE4_WOTH: i64 = 2i64;

pub const MODE4_WUSR: i64 = 128i64;

pub const MODE4_XGRP: i64 = 8i64;

pub const MODE4_XOTH: i64 = 1i64;

pub const MODE4_XUSR: i64 = 64i64;

pub const NFL4_UFLG_COMMIT_THRU_MDS: i64 = 2i64;

pub const NFL4_UFLG_DENSE: i64 = 1i64;

pub const NFL4_UFLG_MASK: i64 = 63i64;

pub const NFL4_UFLG_STRIPE_UNIT_SIZE_MASK: i64 = 192i64;

pub const NFS4_DEVICEID4_SIZE: i64 = 16i64;

pub const NFS4_FHSIZE: i64 = 128i64;

pub const NFS4_INT32_MAX: i64 = 2147483647i64;

pub const NFS4_INT64_MAX: i64 = 2147483647i64;

pub const NFS4_MAXFILELEN: i64 = 4294967295i64;

pub const NFS4_MAXFILEOFF: i64 = 4294967294i64;

pub const NFS4_OPAQUE_LIMIT: i64 = 1024i64;

pub const NFS4_SESSIONID_SIZE: i64 = 16i64;

pub const NFS4_UINT32_MAX: i64 = 4294967295i64;

pub const NFS4_UINT64_MAX: i64 = 4294967295i64;

pub const NFS4_VERIFIER_SIZE: i64 = 8i64;

pub const OPEN4_RESULT_CONFIRM: i64 = 2i64;

pub const OPEN4_RESULT_LOCKTYPE_POSIX: i64 = 4i64;

pub const OPEN4_RESULT_MAY_NOTIFY_LOCK: i64 = 32i64;

pub const OPEN4_RESULT_PRESERVE_UNLINKED: i64 = 8i64;

pub const OPEN4_SHARE_ACCESS_BOTH: i64 = 3i64;

pub const OPEN4_SHARE_ACCESS_READ: i64 = 1i64;

pub const OPEN4_SHARE_ACCESS_WANT_ANY_DELEG: i64 = 768i64;

pub const OPEN4_SHARE_ACCESS_WANT_CANCEL: i64 = 1280i64;

pub const OPEN4_SHARE_ACCESS_WANT_DELEG_MASK: i64 = 65280i64;

pub const OPEN4_SHARE_ACCESS_WANT_NO_DELEG: i64 = 1024i64;

pub const OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE: i64 = 0i64;

pub const OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED: i64 = 65536i64;

pub const OPEN4_SHARE_ACCESS_WANT_READ_DELEG: i64 = 256i64;

pub const OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL: i64 = 65536i64;

pub const OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG: i64 = 512i64;

pub const OPEN4_SHARE_ACCESS_WRITE: i64 = 2i64;

pub const OPEN4_SHARE_DENY_BOTH: i64 = 3i64;

pub const OPEN4_SHARE_DENY_NONE: i64 = 0i64;

pub const OPEN4_SHARE_DENY_READ: i64 = 1i64;

pub const OPEN4_SHARE_DENY_WRITE: i64 = 2i64;

pub const RCA4_TYPE_MASK_BLK_LAYOUT: i64 = 4i64;

pub const RCA4_TYPE_MASK_DIR_DLG: i64 = 2i64;

pub const RCA4_TYPE_MASK_FILE_LAYOUT: i64 = 3i64;

pub const RCA4_TYPE_MASK_OBJ_LAYOUT_MAX: i64 = 9i64;

pub const RCA4_TYPE_MASK_OBJ_LAYOUT_MIN: i64 = 8i64;

pub const RCA4_TYPE_MASK_OTHER_LAYOUT_MAX: i64 = 15i64;

pub const RCA4_TYPE_MASK_OTHER_LAYOUT_MIN: i64 = 12i64;

pub const RCA4_TYPE_MASK_RDATA_DLG: i64 = 0i64;

pub const RCA4_TYPE_MASK_WDATA_DLG: i64 = 1i64;

pub const RET4_DURATION_INFINITE: i64 = 4294967295i64;

pub const SEQ4_STATUS_ADMIN_STATE_REVOKED: i64 = 32i64;

pub const SEQ4_STATUS_BACKCHANNEL_FAULT: i64 = 1024i64;

pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED: i64 = 4i64;

pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING: i64 = 2i64;

pub const SEQ4_STATUS_CB_PATH_DOWN: i64 = 1i64;

pub const SEQ4_STATUS_CB_PATH_DOWN_SESSION: i64 = 512i64;

pub const SEQ4_STATUS_DEVID_CHANGED: i64 = 2048i64;

pub const SEQ4_STATUS_DEVID_DELETED: i64 = 4096i64;

pub const SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED: i64 = 8i64;

pub const SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED: i64 = 16i64;

pub const SEQ4_STATUS_LEASE_MOVED: i64 = 128i64;

pub const SEQ4_STATUS_RECALLABLE_STATE_REVOKED: i64 = 64i64;

pub const SEQ4_STATUS_RESTART_RECLAIM_NEEDED: i64 = 256i64;

pub const TH4_READ_IOSIZE: i64 = 2i64;

pub const TH4_READ_SIZE: i64 = 0i64;

pub const TH4_WRITE_IOSIZE: i64 = 3i64;

pub const TH4_WRITE_SIZE: i64 = 1i64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ACCESS4args {
    pub access: uint32_t,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ACCESS4res {
    NFS4_OK(ACCESS4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ACCESS4resok {
    pub supported: uint32_t,
    pub access: uint32_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AWSFILE_READ_BYPASS4res {
    NFS4_OK(READ4resok),
    NFS4ERR_AWSFILE_BYPASS(AWSFILE_READ_BYPASS4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AWSFILE_READ_BYPASS4resok {
    pub filehandle: nfs_fh4,
    pub data_locator: awsfile_bypass_data_locator,
    pub file_size: uint64_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BACKCHANNEL_CTL4args {
    pub bca_cb_program: uint32_t,
    pub bca_sec_parms: Vec<callback_sec_parms4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BACKCHANNEL_CTL4res {
    pub bcr_status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BIND_CONN_TO_SESSION4args {
    pub bctsa_sessid: sessionid4,
    pub bctsa_dir: channel_dir_from_client4,
    pub bctsa_use_conn_in_rdma_mode: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BIND_CONN_TO_SESSION4res {
    NFS4_OK(BIND_CONN_TO_SESSION4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BIND_CONN_TO_SESSION4resok {
    pub bctsr_sessid: sessionid4,
    pub bctsr_dir: channel_dir_from_server4,
    pub bctsr_use_conn_in_rdma_mode: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_AWSFILE_HEARTBEAT4args {
    pub clientid: clientid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_AWSFILE_HEARTBEAT4res {
    pub hb_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_COMPOUND4args {
    pub tag: utf8str_cs,
    pub minorversion: uint32_t,
    pub callback_ident: uint32_t,
    pub argarray: Vec<nfs_cb_argop4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_COMPOUND4res {
    pub status: nfsstat4,
    pub tag: utf8str_cs,
    pub resarray: Vec<nfs_cb_resop4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_GETATTR4args {
    pub fh: nfs_fh4,
    pub attr_request: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CB_GETATTR4res {
    NFS4_OK(CB_GETATTR4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_GETATTR4resok {
    pub obj_attributes: fattr4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_ILLEGAL4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_LAYOUTRECALL4args {
    pub clora_type: layouttype4,
    pub clora_iomode: layoutiomode4,
    pub clora_changed: bool,
    pub clora_recall: layoutrecall4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_LAYOUTRECALL4res {
    pub clorr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_NOTIFY4args {
    pub cna_stateid: stateid4,
    pub cna_fh: nfs_fh4,
    pub cna_changes: Vec<notify4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_NOTIFY4res {
    pub cnr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_NOTIFY_DEVICEID4args {
    pub cnda_changes: Vec<notify4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_NOTIFY_DEVICEID4res {
    pub cndr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_NOTIFY_LOCK4args {
    pub cnla_fh: nfs_fh4,
    pub cnla_lock_owner: lock_owner4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_NOTIFY_LOCK4res {
    pub cnlr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_PUSH_DELEG4args {
    pub cpda_fh: nfs_fh4,
    pub cpda_delegation: open_delegation4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_PUSH_DELEG4res {
    pub cpdr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALL4args {
    pub stateid: stateid4,
    pub truncate: bool,
    pub fh: nfs_fh4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALL4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALLABLE_OBJ_AVAIL4res {
    pub croa_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALL_ANY4args {
    pub craa_objects_to_keep: uint32_t,
    pub craa_type_mask: bitmap4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALL_ANY4res {
    pub crar_status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALL_SLOT4args {
    pub rsa_target_highest_slotid: slotid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_RECALL_SLOT4res {
    pub rsr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CB_SEQUENCE4args {
    pub csa_sessionid: sessionid4,
    pub csa_sequenceid: sequenceid4,
    pub csa_slotid: slotid4,
    pub csa_highest_slotid: slotid4,
    pub csa_cachethis: bool,
    pub csa_referring_call_lists: Vec<referring_call_list4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CB_SEQUENCE4res {
    NFS4_OK(CB_SEQUENCE4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_SEQUENCE4resok {
    pub csr_sessionid: sessionid4,
    pub csr_sequenceid: sequenceid4,
    pub csr_slotid: slotid4,
    pub csr_highest_slotid: slotid4,
    pub csr_target_highest_slotid: slotid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_WANTS_CANCELLED4args {
    pub cwca_contended_wants_cancelled: bool,
    pub cwca_resourced_wants_cancelled: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CB_WANTS_CANCELLED4res {
    pub cwcr_status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CLOSE4args {
    pub seqid: seqid4,
    pub open_stateid: stateid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CLOSE4res {
    NFS4_OK(stateid4),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct COMMIT4args {
    pub offset: offset4,
    pub count: count4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum COMMIT4res {
    NFS4_OK(COMMIT4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct COMMIT4resok {
    pub writeverf: verifier4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct COMPOUND4args {
    pub tag: utf8str_cs,
    pub minorversion: uint32_t,
    pub argarray: Vec<nfs_argop4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct COMPOUND4res {
    pub status: nfsstat4,
    pub tag: utf8str_cs,
    pub resarray: Vec<nfs_resop4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CREATE4args {
    pub objtype: createtype4,
    pub objname: component4,
    pub createattrs: fattr4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CREATE4res {
    NFS4_OK(CREATE4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CREATE4resok {
    pub cinfo: change_info4,
    pub attrset: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CREATE_SESSION4args {
    pub csa_clientid: clientid4,
    pub csa_sequence: sequenceid4,
    pub csa_flags: uint32_t,
    pub csa_fore_chan_attrs: channel_attrs4,
    pub csa_back_chan_attrs: channel_attrs4,
    pub csa_cb_program: uint32_t,
    pub csa_sec_parms: Vec<callback_sec_parms4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CREATE_SESSION4res {
    NFS4_OK(CREATE_SESSION4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CREATE_SESSION4resok {
    pub csr_sessionid: sessionid4,
    pub csr_sequence: sequenceid4,
    pub csr_flags: uint32_t,
    pub csr_fore_chan_attrs: channel_attrs4,
    pub csr_back_chan_attrs: channel_attrs4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DELEGPURGE4args {
    pub clientid: clientid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DELEGPURGE4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DELEGRETURN4args {
    pub deleg_stateid: stateid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DELEGRETURN4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DESTROY_CLIENTID4args {
    pub dca_clientid: clientid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DESTROY_CLIENTID4res {
    pub dcr_status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DESTROY_SESSION4args {
    pub dsa_sessionid: sessionid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DESTROY_SESSION4res {
    pub dsr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EXCHANGE_ID4args {
    pub eia_clientowner: client_owner4,
    pub eia_flags: uint32_t,
    pub eia_state_protect: state_protect4_a,
    pub eia_client_impl_id: Vec<nfs_impl_id4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EXCHANGE_ID4res {
    NFS4_OK(EXCHANGE_ID4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EXCHANGE_ID4resok {
    pub eir_clientid: clientid4,
    pub eir_sequenceid: sequenceid4,
    pub eir_flags: uint32_t,
    pub eir_state_protect: state_protect4_r,
    pub eir_server_owner: server_owner4,
    pub eir_server_scope: Vec<u8>,
    pub eir_server_impl_id: Vec<nfs_impl_id4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FREE_STATEID4args {
    pub fsa_stateid: stateid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FREE_STATEID4res {
    pub fsr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETATTR4args {
    pub attr_request: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GETATTR4res {
    NFS4_OK(GETATTR4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETATTR4resok {
    pub obj_attributes: fattr4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETDEVICEINFO4args {
    pub gdia_device_id: deviceid4,
    pub gdia_layout_type: layouttype4,
    pub gdia_maxcount: count4,
    pub gdia_notify_types: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GETDEVICEINFO4res {
    NFS4_OK(GETDEVICEINFO4resok),
    NFS4ERR_TOOSMALL(count4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETDEVICEINFO4resok {
    pub gdir_device_addr: device_addr4,
    pub gdir_notification: bitmap4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GETDEVICELIST4args {
    pub gdla_layout_type: layouttype4,
    pub gdla_maxdevices: count4,
    pub gdla_cookie: nfs_cookie4,
    pub gdla_cookieverf: verifier4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GETDEVICELIST4res {
    NFS4_OK(GETDEVICELIST4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETDEVICELIST4resok {
    pub gdlr_cookie: nfs_cookie4,
    pub gdlr_cookieverf: verifier4,
    pub gdlr_deviceid_list: Vec<deviceid4>,
    pub gdlr_eof: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GETFH4res {
    NFS4_OK(GETFH4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETFH4resok {
    pub object: nfs_fh4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GETXATTR4args {
    pub gxa_name: xattrkey4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GETXATTR4res {
    NFS4_OK(xattrvalue4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GET_DIR_DELEGATION4args {
    pub gdda_signal_deleg_avail: bool,
    pub gdda_notification_types: bitmap4,
    pub gdda_child_attr_delay: attr_notice4,
    pub gdda_dir_attr_delay: attr_notice4,
    pub gdda_child_attributes: bitmap4,
    pub gdda_dir_attributes: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GET_DIR_DELEGATION4res {
    NFS4_OK(GET_DIR_DELEGATION4res_non_fatal),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GET_DIR_DELEGATION4res_non_fatal {
    GDD4_OK(GET_DIR_DELEGATION4resok),
    GDD4_UNAVAIL(bool),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GET_DIR_DELEGATION4resok {
    pub gddr_cookieverf: verifier4,
    pub gddr_stateid: stateid4,
    pub gddr_notification: bitmap4,
    pub gddr_child_attributes: bitmap4,
    pub gddr_dir_attributes: bitmap4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ILLEGAL4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LAYOUTCOMMIT4args {
    pub loca_offset: offset4,
    pub loca_length: length4,
    pub loca_reclaim: bool,
    pub loca_stateid: stateid4,
    pub loca_last_write_offset: newoffset4,
    pub loca_time_modify: newtime4,
    pub loca_layoutupdate: layoutupdate4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LAYOUTCOMMIT4res {
    NFS4_OK(LAYOUTCOMMIT4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LAYOUTCOMMIT4resok {
    pub locr_newsize: newsize4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LAYOUTGET4args {
    pub loga_signal_layout_avail: bool,
    pub loga_layout_type: layouttype4,
    pub loga_iomode: layoutiomode4,
    pub loga_offset: offset4,
    pub loga_length: length4,
    pub loga_minlength: length4,
    pub loga_stateid: stateid4,
    pub loga_maxcount: count4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LAYOUTGET4res {
    NFS4_OK(LAYOUTGET4resok),
    NFS4ERR_LAYOUTTRYLATER(bool),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LAYOUTGET4resok {
    pub logr_return_on_close: bool,
    pub logr_stateid: stateid4,
    pub logr_layout: Vec<layout4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LAYOUTRETURN4args {
    pub lora_reclaim: bool,
    pub lora_layout_type: layouttype4,
    pub lora_iomode: layoutiomode4,
    pub lora_layoutreturn: layoutreturn4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LAYOUTRETURN4res {
    NFS4_OK(layoutreturn_stateid),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LINK4args {
    pub newname: component4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LINK4res {
    NFS4_OK(LINK4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LINK4resok {
    pub cinfo: change_info4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LISTXATTRS4args {
    pub lxa_cookie: nfs_cookie4,
    pub lxa_maxcount: count4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LISTXATTRS4res {
    NFS4_OK(LISTXATTRS4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LISTXATTRS4resok {
    pub lxr_cookie: nfs_cookie4,
    pub lxr_names: Vec<xattrkey4>,
    pub lxr_eof: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LOCK4args {
    pub locktype: nfs_lock_type4,
    pub reclaim: bool,
    pub offset: offset4,
    pub length: length4,
    pub locker: locker4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LOCK4denied {
    pub offset: offset4,
    pub length: length4,
    pub locktype: nfs_lock_type4,
    pub owner: lock_owner4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LOCK4res {
    NFS4_OK(LOCK4resok),
    NFS4ERR_DENIED(LOCK4denied),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LOCK4resok {
    pub lock_stateid: stateid4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LOCKT4args {
    pub locktype: nfs_lock_type4,
    pub offset: offset4,
    pub length: length4,
    pub owner: lock_owner4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LOCKT4res {
    NFS4ERR_DENIED(LOCK4denied),
    NFS4_OK,
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LOCKU4args {
    pub locktype: nfs_lock_type4,
    pub seqid: seqid4,
    pub lock_stateid: stateid4,
    pub offset: offset4,
    pub length: length4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LOCKU4res {
    NFS4_OK(stateid4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LOOKUP4args {
    pub objname: component4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LOOKUP4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LOOKUPP4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NVERIFY4args {
    pub obj_attributes: fattr4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NVERIFY4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OPEN4args {
    pub seqid: seqid4,
    pub share_access: uint32_t,
    pub share_deny: uint32_t,
    pub owner: open_owner4,
    pub openhow: openflag4,
    pub claim: open_claim4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OPEN4res {
    NFS4_OK(OPEN4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OPEN4resok {
    pub stateid: stateid4,
    pub cinfo: change_info4,
    pub rflags: uint32_t,
    pub attrset: bitmap4,
    pub delegation: open_delegation4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OPENATTR4args {
    pub createdir: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OPENATTR4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OPEN_CONFIRM4args {
    pub open_stateid: stateid4,
    pub seqid: seqid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OPEN_CONFIRM4res {
    NFS4_OK(OPEN_CONFIRM4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OPEN_CONFIRM4resok {
    pub open_stateid: stateid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OPEN_DOWNGRADE4args {
    pub open_stateid: stateid4,
    pub seqid: seqid4,
    pub share_access: uint32_t,
    pub share_deny: uint32_t,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OPEN_DOWNGRADE4res {
    NFS4_OK(OPEN_DOWNGRADE4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OPEN_DOWNGRADE4resok {
    pub open_stateid: stateid4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PUTFH4args {
    pub object: nfs_fh4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PUTFH4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PUTPUBFH4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PUTROOTFH4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct READ4args {
    pub stateid: stateid4,
    pub offset: offset4,
    pub count: count4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum READ4res {
    NFS4_OK(READ4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct READ4resok {
    pub eof: bool,
    pub data: DataPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct READDIR4args {
    pub cookie: nfs_cookie4,
    pub cookieverf: verifier4,
    pub dircount: count4,
    pub maxcount: count4,
    pub attr_request: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum READDIR4res {
    NFS4_OK(READDIR4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct READDIR4resok {
    pub cookieverf: verifier4,
    pub reply: dirlist4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum READLINK4res {
    NFS4_OK(READLINK4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct READLINK4resok {
    pub link: linktext4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RECLAIM_COMPLETE4args {
    pub rca_one_fs: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RECLAIM_COMPLETE4res {
    pub rcr_status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RELEASE_LOCKOWNER4args {
    pub lock_owner: lock_owner4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RELEASE_LOCKOWNER4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct REMOVE4args {
    pub target: component4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum REMOVE4res {
    NFS4_OK(REMOVE4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct REMOVE4resok {
    pub cinfo: change_info4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct REMOVEXATTR4args {
    pub rxa_name: xattrkey4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum REMOVEXATTR4res {
    NFS4_OK(change_info4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RENAME4args {
    pub oldname: component4,
    pub newname: component4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RENAME4res {
    NFS4_OK(RENAME4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RENAME4resok {
    pub source_cinfo: change_info4,
    pub target_cinfo: change_info4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RENEW4args {
    pub clientid: clientid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RENEW4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RESTOREFH4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SAVEFH4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SECINFO4args {
    pub name: component4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SECINFO4res {
    NFS4_OK(SECINFO4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SECINFO4resok(pub Vec<secinfo4>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SEQUENCE4args {
    pub sa_sessionid: sessionid4,
    pub sa_sequenceid: sequenceid4,
    pub sa_slotid: slotid4,
    pub sa_highest_slotid: slotid4,
    pub sa_cachethis: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SEQUENCE4res {
    NFS4_OK(SEQUENCE4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SEQUENCE4resok {
    pub sr_sessionid: sessionid4,
    pub sr_sequenceid: sequenceid4,
    pub sr_slotid: slotid4,
    pub sr_highest_slotid: slotid4,
    pub sr_target_highest_slotid: slotid4,
    pub sr_status_flags: uint32_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SETATTR4args {
    pub stateid: stateid4,
    pub obj_attributes: fattr4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SETATTR4res {
    pub status: nfsstat4,
    pub attrsset: bitmap4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SETCLIENTID4args {
    pub client: nfs_client_id4,
    pub callback: cb_client4,
    pub callback_ident: uint32_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SETCLIENTID4res {
    NFS4_OK(SETCLIENTID4resok),
    NFS4ERR_CLID_INUSE(clientaddr4),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SETCLIENTID4resok {
    pub clientid: clientid4,
    pub setclientid_confirm: verifier4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SETCLIENTID_CONFIRM4args {
    pub clientid: clientid4,
    pub setclientid_confirm: verifier4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SETCLIENTID_CONFIRM4res {
    pub status: nfsstat4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SETXATTR4args {
    pub sxa_option: setxattr_option4,
    pub sxa_key: xattrkey4,
    pub sxa_value: xattrvalue4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SETXATTR4res {
    NFS4_OK(change_info4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SET_SSV4args {
    pub ssa_ssv: Vec<u8>,
    pub ssa_digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SET_SSV4res {
    NFS4_OK(SET_SSV4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SET_SSV4resok {
    pub ssr_digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TEST_STATEID4args {
    pub ts_stateids: Vec<stateid4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TEST_STATEID4res {
    NFS4_OK(TEST_STATEID4resok),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TEST_STATEID4resok {
    pub tsr_status_codes: Vec<nfsstat4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VERIFY4args {
    pub obj_attributes: fattr4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VERIFY4res {
    pub status: nfsstat4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WANT_DELEGATION4args {
    pub wda_want: uint32_t,
    pub wda_claim: deleg_claim4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WANT_DELEGATION4res {
    NFS4_OK(open_delegation4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataPayload {
    Data(Bytes),
    DataRef(OpaqueRaw),
}

/// Represents a slice of opaque data within a larger buffer,
/// defined by its starting offset and length.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OpaqueRaw {
    /// The starting position (byte offset) of the data slice within a the *compound* buffer.
    /// Note: this is after the "4 byte opaque data length", directly pointing at the beginning of the real data buffer.
    pub offset: usize,
    /// The length of the data slice in bytes.
    pub len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WRITE4args {
    pub stateid: stateid4,
    pub offset: offset4,
    pub stable: stable_how4,
    pub data: DataPayload,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WRITE4res {
    NFS4_OK(WRITE4resok),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WRITE4resok {
    pub count: count4,
    pub committed: stable_how4,
    pub writeverf: verifier4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct attrlist4(pub Vec<u8>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum auth_flavor4 {
    AUTH_NONE = 0isize,
    AUTH_SYS = 1isize,
    RPCSEC_GSS = 6isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct authsys_parms {
    pub stamp: uint32_t,
    pub machinename: utf8str_cs,
    pub uid: uint32_t,
    pub gid: uint32_t,
    pub gids: Vec<uint32_t>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct awsfile_bypass_data_locator {
    pub bucket_name: Vec<u8>,
    pub s3_key: Vec<u8>,
    pub etag: Vec<u8>,
    pub version_id: Vec<u8>,
    pub offset: offset4,
    pub count: count4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct bitmap4(pub Vec<uint32_t>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum boolflag {
    FALSE = 0isize,
    TRUE = 1isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum callback_sec_parms4 {
    AUTH_NONE,
    AUTH_SYS(authsys_parms),
    RPCSEC_GSS(gss_cb_handles4),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct cb_client4 {
    pub cb_program: uint32_t,
    pub cb_location: netaddr4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct change_info4 {
    pub atomic: bool,
    pub before: changeid4,
    pub after: changeid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct change_policy4 {
    pub cp_major: uint64_t,
    pub cp_minor: uint64_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct channel_attrs4 {
    pub ca_headerpadsize: count4,
    pub ca_maxrequestsize: count4,
    pub ca_maxresponsesize: count4,
    pub ca_maxresponsesize_cached: count4,
    pub ca_maxoperations: count4,
    pub ca_maxrequests: count4,
    pub ca_rdma_ird: Vec<uint32_t>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum channel_dir_from_client4 {
    CDFC4_FORE = 1isize,
    CDFC4_BACK = 2isize,
    CDFC4_FORE_OR_BOTH = 3isize,
    CDFC4_BACK_OR_BOTH = 7isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum channel_dir_from_server4 {
    CDFS4_FORE = 1isize,
    CDFS4_BACK = 2isize,
    CDFS4_BOTH = 3isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct client_owner4 {
    pub co_verifier: verifier4,
    pub co_ownerid: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum createhow4 {
    UNCHECKED4(fattr4),
    GUARDED4(fattr4),
    EXCLUSIVE4(verifier4),
    EXCLUSIVE4_1(creatverfattr),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum createmode4 {
    UNCHECKED4 = 0isize,
    GUARDED4 = 1isize,
    EXCLUSIVE4 = 2isize,
    EXCLUSIVE4_1 = 3isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum createtype4 {
    NF4LNK(linktext4),
    NF4BLK(specdata4),
    NF4CHR(specdata4),
    NF4SOCK,
    NF4FIFO,
    NF4DIR,
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct creatverfattr {
    pub cva_verf: verifier4,
    pub cva_attrs: fattr4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum deleg_claim4 {
    CLAIM_FH,
    CLAIM_DELEG_PREV_FH,
    CLAIM_PREVIOUS(open_delegation_type4),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct device_addr4 {
    pub da_layout_type: layouttype4,
    pub da_addr_body: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct deviceid4(pub [u8; NFS4_DEVICEID4_SIZE as usize]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct dirlist4 {
    pub entries: Option<Box<entry4>>,
    pub eof: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct entry4 {
    pub cookie: nfs_cookie4,
    pub name: component4,
    pub attrs: fattr4,
    pub nextentry: Option<Box<entry4>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct exist_lock_owner4 {
    pub lock_stateid: stateid4,
    pub lock_seqid: seqid4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fattr4 {
    pub attrmask: bitmap4,
    pub attr_vals: attrlist4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fattr4_acl(pub Vec<nfsace4>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fattr4_fs_layout_types(pub Vec<layouttype4>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fattr4_layout_types(pub Vec<layouttype4>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum filelayout_hint_care4 {
    NFLH4_CARE_DENSE = 1isize,
    NFLH4_CARE_COMMIT_THRU_MDS = 2isize,
    NFLH4_CARE_STRIPE_UNIT_SIZE = 64isize,
    NFLH4_CARE_STRIPE_COUNT = 128isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fs4_status {
    pub fss_absent: bool,
    pub fss_type: fs4_status_type,
    pub fss_source: utf8str_cs,
    pub fss_current: utf8str_cs,
    pub fss_age: int32_t,
    pub fss_version: nfstime4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum fs4_status_type {
    STATUS4_FIXED = 1isize,
    STATUS4_UPDATED = 2isize,
    STATUS4_VERSIONED = 3isize,
    STATUS4_WRITABLE = 4isize,
    STATUS4_REFERRAL = 5isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fs_location4 {
    pub server: Vec<utf8str_cis>,
    pub rootpath: pathname4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fs_locations4 {
    pub fs_root: pathname4,
    pub locations: Vec<fs_location4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fs_locations_info4 {
    pub fli_flags: uint32_t,
    pub fli_valid_for: int32_t,
    pub fli_fs_root: pathname4,
    pub fli_items: Vec<fs_locations_item4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fs_locations_item4 {
    pub fli_entries: Vec<fs_locations_server4>,
    pub fli_rootpath: pathname4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct fs_locations_server4 {
    pub fls_currency: int32_t,
    pub fls_info: Vec<u8>,
    pub fls_server: utf8str_cis,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct fsid4 {
    pub major: uint64_t,
    pub minor: uint64_t,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum gddrnf4_status {
    GDD4_OK = 0isize,
    GDD4_UNAVAIL = 1isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct gss_cb_handles4 {
    pub gcbp_service: rpc_gss_svc_t,
    pub gcbp_handle_from_server: gsshandle4_t,
    pub gcbp_handle_from_client: gsshandle4_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct gsshandle4_t(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct layout4 {
    pub lo_offset: offset4,
    pub lo_length: length4,
    pub lo_iomode: layoutiomode4,
    pub lo_content: layout_content4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct layout_content4 {
    pub loc_type: layouttype4,
    pub loc_body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct layouthint4 {
    pub loh_type: layouttype4,
    pub loh_body: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum layoutiomode4 {
    LAYOUTIOMODE4_READ = 1isize,
    LAYOUTIOMODE4_RW = 2isize,
    LAYOUTIOMODE4_ANY = 3isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum layoutrecall4 {
    LAYOUTRECALL4_FILE(layoutrecall_file4),
    LAYOUTRECALL4_FSID(fsid4),
    LAYOUTRECALL4_ALL,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct layoutrecall_file4 {
    pub lor_fh: nfs_fh4,
    pub lor_offset: offset4,
    pub lor_length: length4,
    pub lor_stateid: stateid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum layoutrecall_type4 {
    LAYOUTRECALL4_FILE = 1isize,
    LAYOUTRECALL4_FSID = 2isize,
    LAYOUTRECALL4_ALL = 3isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum layoutreturn4 {
    LAYOUTRETURN4_FILE(layoutreturn_file4),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct layoutreturn_file4 {
    pub lrf_offset: offset4,
    pub lrf_length: length4,
    pub lrf_stateid: stateid4,
    pub lrf_body: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum layoutreturn_stateid {
    TRUE(stateid4),
    FALSE,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum layoutreturn_type4 {
    LAYOUTRETURN4_FILE = 1isize,
    LAYOUTRETURN4_FSID = 2isize,
    LAYOUTRETURN4_ALL = 3isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum layouttype4 {
    LAYOUT4_NFSV4_1_FILES = 1isize,
    LAYOUT4_OSD2_OBJECTS = 2isize,
    LAYOUT4_BLOCK_VOLUME = 3isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct layoutupdate4 {
    pub lou_type: layouttype4,
    pub lou_body: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum limit_by4 {
    NFS_LIMIT_SIZE = 1isize,
    NFS_LIMIT_BLOCKS = 2isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum locker4 {
    TRUE(open_to_lock_owner4),
    FALSE(exist_lock_owner4),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct mdsthreshold4 {
    pub mth_hints: Vec<threshold_item4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct mode_masked4 {
    pub mm_value_to_set: mode4,
    pub mm_mask_bits: mode4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct multipath_list4(pub Vec<netaddr4>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct netaddr4 {
    pub na_r_netid: String,
    pub na_r_addr: String,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum newoffset4 {
    TRUE(offset4),
    FALSE,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum newsize4 {
    TRUE(length4),
    FALSE,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum newtime4 {
    TRUE(nfstime4),
    FALSE,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum nfs_argop4 {
    OP_ACCESS(ACCESS4args),
    OP_CLOSE(CLOSE4args),
    OP_COMMIT(COMMIT4args),
    OP_CREATE(CREATE4args),
    OP_DELEGPURGE(DELEGPURGE4args),
    OP_DELEGRETURN(DELEGRETURN4args),
    OP_GETATTR(GETATTR4args),
    OP_GETFH,
    OP_LINK(LINK4args),
    OP_LOCK(LOCK4args),
    OP_LOCKT(LOCKT4args),
    OP_LOCKU(LOCKU4args),
    OP_LOOKUP(LOOKUP4args),
    OP_LOOKUPP,
    OP_NVERIFY(NVERIFY4args),
    OP_OPEN(OPEN4args),
    OP_OPENATTR(OPENATTR4args),
    OP_OPEN_CONFIRM(OPEN_CONFIRM4args),
    OP_OPEN_DOWNGRADE(OPEN_DOWNGRADE4args),
    OP_PUTFH(PUTFH4args),
    OP_PUTPUBFH,
    OP_PUTROOTFH,
    OP_READ(READ4args),
    OP_READDIR(READDIR4args),
    OP_READLINK,
    OP_REMOVE(REMOVE4args),
    OP_RENAME(RENAME4args),
    OP_RENEW(RENEW4args),
    OP_RESTOREFH,
    OP_SAVEFH,
    OP_SECINFO(SECINFO4args),
    OP_SETATTR(SETATTR4args),
    OP_SETCLIENTID(SETCLIENTID4args),
    OP_SETCLIENTID_CONFIRM(SETCLIENTID_CONFIRM4args),
    OP_VERIFY(VERIFY4args),
    OP_WRITE(WRITE4args),
    OP_RELEASE_LOCKOWNER(RELEASE_LOCKOWNER4args),
    OP_BACKCHANNEL_CTL(BACKCHANNEL_CTL4args),
    OP_BIND_CONN_TO_SESSION(BIND_CONN_TO_SESSION4args),
    OP_EXCHANGE_ID(EXCHANGE_ID4args),
    OP_CREATE_SESSION(CREATE_SESSION4args),
    OP_DESTROY_SESSION(DESTROY_SESSION4args),
    OP_FREE_STATEID(FREE_STATEID4args),
    OP_GET_DIR_DELEGATION(GET_DIR_DELEGATION4args),
    OP_GETDEVICEINFO(GETDEVICEINFO4args),
    OP_GETDEVICELIST(GETDEVICELIST4args),
    OP_LAYOUTCOMMIT(LAYOUTCOMMIT4args),
    OP_LAYOUTGET(LAYOUTGET4args),
    OP_LAYOUTRETURN(LAYOUTRETURN4args),
    OP_SECINFO_NO_NAME(SECINFO_NO_NAME4args),
    OP_SEQUENCE(SEQUENCE4args),
    OP_SET_SSV(SET_SSV4args),
    OP_TEST_STATEID(TEST_STATEID4args),
    OP_WANT_DELEGATION(WANT_DELEGATION4args),
    OP_DESTROY_CLIENTID(DESTROY_CLIENTID4args),
    OP_RECLAIM_COMPLETE(RECLAIM_COMPLETE4args),
    OP_GETXATTR(GETXATTR4args),
    OP_SETXATTR(SETXATTR4args),
    OP_LISTXATTRS(LISTXATTRS4args),
    OP_REMOVEXATTR(REMOVEXATTR4args),
    OP_ILLEGAL,
    OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4args),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum nfs_cb_argop4 {
    OP_CB_GETATTR(CB_GETATTR4args),
    OP_CB_RECALL(CB_RECALL4args),
    OP_CB_LAYOUTRECALL(CB_LAYOUTRECALL4args),
    OP_CB_NOTIFY(CB_NOTIFY4args),
    OP_CB_PUSH_DELEG(CB_PUSH_DELEG4args),
    OP_CB_RECALL_ANY(CB_RECALL_ANY4args),
    OP_CB_RECALLABLE_OBJ_AVAIL(CB_RECALLABLE_OBJ_AVAIL4args),
    OP_CB_RECALL_SLOT(CB_RECALL_SLOT4args),
    OP_CB_SEQUENCE(CB_SEQUENCE4args),
    OP_CB_WANTS_CANCELLED(CB_WANTS_CANCELLED4args),
    OP_CB_NOTIFY_LOCK(CB_NOTIFY_LOCK4args),
    OP_CB_NOTIFY_DEVICEID(CB_NOTIFY_DEVICEID4args),
    OP_CB_ILLEGAL,
    OP_CB_AWSFILE_HEARTBEAT(CB_AWSFILE_HEARTBEAT4args),
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum nfs_cb_opnum4 {
    OP_CB_GETATTR = 3isize,
    OP_CB_RECALL = 4isize,
    OP_CB_LAYOUTRECALL = 5isize,
    OP_CB_NOTIFY = 6isize,
    OP_CB_PUSH_DELEG = 7isize,
    OP_CB_RECALL_ANY = 8isize,
    OP_CB_RECALLABLE_OBJ_AVAIL = 9isize,
    OP_CB_RECALL_SLOT = 10isize,
    OP_CB_SEQUENCE = 11isize,
    OP_CB_WANTS_CANCELLED = 12isize,
    OP_CB_NOTIFY_LOCK = 13isize,
    OP_CB_NOTIFY_DEVICEID = 14isize,
    OP_CB_ILLEGAL = 10044isize,
    OP_CB_AWSFILE_HEARTBEAT = 100001isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum nfs_cb_resop4 {
    OP_CB_GETATTR(CB_GETATTR4res),
    OP_CB_RECALL(CB_RECALL4res),
    OP_CB_LAYOUTRECALL(CB_LAYOUTRECALL4res),
    OP_CB_NOTIFY(CB_NOTIFY4res),
    OP_CB_PUSH_DELEG(CB_PUSH_DELEG4res),
    OP_CB_RECALL_ANY(CB_RECALL_ANY4res),
    OP_CB_RECALLABLE_OBJ_AVAIL(CB_RECALLABLE_OBJ_AVAIL4res),
    OP_CB_RECALL_SLOT(CB_RECALL_SLOT4res),
    OP_CB_SEQUENCE(CB_SEQUENCE4res),
    OP_CB_WANTS_CANCELLED(CB_WANTS_CANCELLED4res),
    OP_CB_NOTIFY_LOCK(CB_NOTIFY_LOCK4res),
    OP_CB_NOTIFY_DEVICEID(CB_NOTIFY_DEVICEID4res),
    OP_CB_ILLEGAL(CB_ILLEGAL4res),
    OP_CB_AWSFILE_HEARTBEAT(CB_AWSFILE_HEARTBEAT4res),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct nfs_client_id4 {
    pub verifier: verifier4,
    pub id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct nfs_fh4(pub Vec<u8>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum nfs_ftype4 {
    NF4REG = 1isize,
    NF4DIR = 2isize,
    NF4BLK = 3isize,
    NF4CHR = 4isize,
    NF4LNK = 5isize,
    NF4SOCK = 6isize,
    NF4FIFO = 7isize,
    NF4ATTRDIR = 8isize,
    NF4NAMEDATTR = 9isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct nfs_impl_id4 {
    pub nii_domain: utf8str_cis,
    pub nii_name: utf8str_cs,
    pub nii_date: nfstime4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum nfs_lock_type4 {
    READ_LT = 1isize,
    WRITE_LT = 2isize,
    READW_LT = 3isize,
    WRITEW_LT = 4isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct nfs_modified_limit4 {
    pub num_blocks: uint32_t,
    pub bytes_per_block: uint32_t,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum nfs_opnum4 {
    OP_ACCESS = 3isize,
    OP_CLOSE = 4isize,
    OP_COMMIT = 5isize,
    OP_CREATE = 6isize,
    OP_DELEGPURGE = 7isize,
    OP_DELEGRETURN = 8isize,
    OP_GETATTR = 9isize,
    OP_GETFH = 10isize,
    OP_LINK = 11isize,
    OP_LOCK = 12isize,
    OP_LOCKT = 13isize,
    OP_LOCKU = 14isize,
    OP_LOOKUP = 15isize,
    OP_LOOKUPP = 16isize,
    OP_NVERIFY = 17isize,
    OP_OPEN = 18isize,
    OP_OPENATTR = 19isize,
    OP_OPEN_CONFIRM = 20isize,
    OP_OPEN_DOWNGRADE = 21isize,
    OP_PUTFH = 22isize,
    OP_PUTPUBFH = 23isize,
    OP_PUTROOTFH = 24isize,
    OP_READ = 25isize,
    OP_READDIR = 26isize,
    OP_READLINK = 27isize,
    OP_REMOVE = 28isize,
    OP_RENAME = 29isize,
    OP_RENEW = 30isize,
    OP_RESTOREFH = 31isize,
    OP_SAVEFH = 32isize,
    OP_SECINFO = 33isize,
    OP_SETATTR = 34isize,
    OP_SETCLIENTID = 35isize,
    OP_SETCLIENTID_CONFIRM = 36isize,
    OP_VERIFY = 37isize,
    OP_WRITE = 38isize,
    OP_RELEASE_LOCKOWNER = 39isize,
    OP_BACKCHANNEL_CTL = 40isize,
    OP_BIND_CONN_TO_SESSION = 41isize,
    OP_EXCHANGE_ID = 42isize,
    OP_CREATE_SESSION = 43isize,
    OP_DESTROY_SESSION = 44isize,
    OP_FREE_STATEID = 45isize,
    OP_GET_DIR_DELEGATION = 46isize,
    OP_GETDEVICEINFO = 47isize,
    OP_GETDEVICELIST = 48isize,
    OP_LAYOUTCOMMIT = 49isize,
    OP_LAYOUTGET = 50isize,
    OP_LAYOUTRETURN = 51isize,
    OP_SECINFO_NO_NAME = 52isize,
    OP_SEQUENCE = 53isize,
    OP_SET_SSV = 54isize,
    OP_TEST_STATEID = 55isize,
    OP_WANT_DELEGATION = 56isize,
    OP_DESTROY_CLIENTID = 57isize,
    OP_RECLAIM_COMPLETE = 58isize,
    OP_GETXATTR = 72isize,
    OP_SETXATTR = 73isize,
    OP_LISTXATTRS = 74isize,
    OP_REMOVEXATTR = 75isize,
    OP_ILLEGAL = 10044isize,
    OP_AWSFILE_READ_BYPASS = 200001isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum nfs_resop4 {
    OP_ACCESS(ACCESS4res),
    OP_CLOSE(CLOSE4res),
    OP_COMMIT(COMMIT4res),
    OP_CREATE(CREATE4res),
    OP_DELEGPURGE(DELEGPURGE4res),
    OP_DELEGRETURN(DELEGRETURN4res),
    OP_GETATTR(GETATTR4res),
    OP_GETFH(GETFH4res),
    OP_LINK(LINK4res),
    OP_LOCK(LOCK4res),
    OP_LOCKT(LOCKT4res),
    OP_LOCKU(LOCKU4res),
    OP_LOOKUP(LOOKUP4res),
    OP_LOOKUPP(LOOKUPP4res),
    OP_NVERIFY(NVERIFY4res),
    OP_OPEN(OPEN4res),
    OP_OPENATTR(OPENATTR4res),
    OP_OPEN_CONFIRM(OPEN_CONFIRM4res),
    OP_OPEN_DOWNGRADE(OPEN_DOWNGRADE4res),
    OP_PUTFH(PUTFH4res),
    OP_PUTPUBFH(PUTPUBFH4res),
    OP_PUTROOTFH(PUTROOTFH4res),
    OP_READ(READ4res),
    OP_READDIR(READDIR4res),
    OP_READLINK(READLINK4res),
    OP_REMOVE(REMOVE4res),
    OP_RENAME(RENAME4res),
    OP_RENEW(RENEW4res),
    OP_RESTOREFH(RESTOREFH4res),
    OP_SAVEFH(SAVEFH4res),
    OP_SECINFO(SECINFO4res),
    OP_SETATTR(SETATTR4res),
    OP_SETCLIENTID(SETCLIENTID4res),
    OP_SETCLIENTID_CONFIRM(SETCLIENTID_CONFIRM4res),
    OP_VERIFY(VERIFY4res),
    OP_WRITE(WRITE4res),
    OP_RELEASE_LOCKOWNER(RELEASE_LOCKOWNER4res),
    OP_BACKCHANNEL_CTL(BACKCHANNEL_CTL4res),
    OP_BIND_CONN_TO_SESSION(BIND_CONN_TO_SESSION4res),
    OP_EXCHANGE_ID(EXCHANGE_ID4res),
    OP_CREATE_SESSION(CREATE_SESSION4res),
    OP_DESTROY_SESSION(DESTROY_SESSION4res),
    OP_FREE_STATEID(FREE_STATEID4res),
    OP_GET_DIR_DELEGATION(GET_DIR_DELEGATION4res),
    OP_GETDEVICEINFO(GETDEVICEINFO4res),
    OP_GETDEVICELIST(GETDEVICELIST4res),
    OP_LAYOUTCOMMIT(LAYOUTCOMMIT4res),
    OP_LAYOUTGET(LAYOUTGET4res),
    OP_LAYOUTRETURN(LAYOUTRETURN4res),
    OP_SECINFO_NO_NAME(SECINFO_NO_NAME4res),
    OP_SEQUENCE(SEQUENCE4res),
    OP_SET_SSV(SET_SSV4res),
    OP_TEST_STATEID(TEST_STATEID4res),
    OP_WANT_DELEGATION(WANT_DELEGATION4res),
    OP_DESTROY_CLIENTID(DESTROY_CLIENTID4res),
    OP_RECLAIM_COMPLETE(RECLAIM_COMPLETE4res),
    OP_GETXATTR(GETXATTR4res),
    OP_SETXATTR(SETXATTR4res),
    OP_LISTXATTRS(LISTXATTRS4res),
    OP_REMOVEXATTR(REMOVEXATTR4res),
    OP_ILLEGAL(ILLEGAL4res),
    OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum nfs_space_limit4 {
    NFS_LIMIT_SIZE(uint64_t),
    NFS_LIMIT_BLOCKS(nfs_modified_limit4),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct nfsace4 {
    pub type_: acetype4,
    pub flag: aceflag4,
    pub access_mask: acemask4,
    pub who: utf8str_mixed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct nfsacl41 {
    pub na41_flag: aclflag4,
    pub na41_aces: Vec<nfsace4>,
}

#[derive(Copy, Clone, Debug, strum_macros::Display, thiserror::Error, Eq, PartialEq)]
pub enum nfsstat4 {
    NFS4_OK = 0isize,
    NFS4ERR_PERM = 1isize,
    NFS4ERR_NOENT = 2isize,
    NFS4ERR_IO = 5isize,
    NFS4ERR_NXIO = 6isize,
    NFS4ERR_ACCESS = 13isize,
    NFS4ERR_EXIST = 17isize,
    NFS4ERR_XDEV = 18isize,
    NFS4ERR_NOTDIR = 20isize,
    NFS4ERR_ISDIR = 21isize,
    NFS4ERR_INVAL = 22isize,
    NFS4ERR_FBIG = 27isize,
    NFS4ERR_NOSPC = 28isize,
    NFS4ERR_ROFS = 30isize,
    NFS4ERR_MLINK = 31isize,
    NFS4ERR_NAMETOOLONG = 63isize,
    NFS4ERR_NOTEMPTY = 66isize,
    NFS4ERR_DQUOT = 69isize,
    NFS4ERR_STALE = 70isize,
    NFS4ERR_BADHANDLE = 10001isize,
    NFS4ERR_BAD_COOKIE = 10003isize,
    NFS4ERR_NOTSUPP = 10004isize,
    NFS4ERR_TOOSMALL = 10005isize,
    NFS4ERR_SERVERFAULT = 10006isize,
    NFS4ERR_BADTYPE = 10007isize,
    NFS4ERR_DELAY = 10008isize,
    NFS4ERR_SAME = 10009isize,
    NFS4ERR_DENIED = 10010isize,
    NFS4ERR_EXPIRED = 10011isize,
    NFS4ERR_LOCKED = 10012isize,
    NFS4ERR_GRACE = 10013isize,
    NFS4ERR_FHEXPIRED = 10014isize,
    NFS4ERR_SHARE_DENIED = 10015isize,
    NFS4ERR_WRONGSEC = 10016isize,
    NFS4ERR_CLID_INUSE = 10017isize,
    NFS4ERR_RESOURCE = 10018isize,
    NFS4ERR_MOVED = 10019isize,
    NFS4ERR_NOFILEHANDLE = 10020isize,
    NFS4ERR_MINOR_VERS_MISMATCH = 10021isize,
    NFS4ERR_STALE_CLIENTID = 10022isize,
    NFS4ERR_STALE_STATEID = 10023isize,
    NFS4ERR_OLD_STATEID = 10024isize,
    NFS4ERR_BAD_STATEID = 10025isize,
    NFS4ERR_BAD_SEQID = 10026isize,
    NFS4ERR_NOT_SAME = 10027isize,
    NFS4ERR_LOCK_RANGE = 10028isize,
    NFS4ERR_SYMLINK = 10029isize,
    NFS4ERR_RESTOREFH = 10030isize,
    NFS4ERR_LEASE_MOVED = 10031isize,
    NFS4ERR_ATTRNOTSUPP = 10032isize,
    NFS4ERR_NO_GRACE = 10033isize,
    NFS4ERR_RECLAIM_BAD = 10034isize,
    NFS4ERR_RECLAIM_CONFLICT = 10035isize,
    NFS4ERR_BADXDR = 10036isize,
    NFS4ERR_LOCKS_HELD = 10037isize,
    NFS4ERR_OPENMODE = 10038isize,
    NFS4ERR_BADOWNER = 10039isize,
    NFS4ERR_BADCHAR = 10040isize,
    NFS4ERR_BADNAME = 10041isize,
    NFS4ERR_BAD_RANGE = 10042isize,
    NFS4ERR_LOCK_NOTSUPP = 10043isize,
    NFS4ERR_OP_ILLEGAL = 10044isize,
    NFS4ERR_DEADLOCK = 10045isize,
    NFS4ERR_FILE_OPEN = 10046isize,
    NFS4ERR_ADMIN_REVOKED = 10047isize,
    NFS4ERR_CB_PATH_DOWN = 10048isize,
    NFS4ERR_BADIOMODE = 10049isize,
    NFS4ERR_BADLAYOUT = 10050isize,
    NFS4ERR_BAD_SESSION_DIGEST = 10051isize,
    NFS4ERR_BADSESSION = 10052isize,
    NFS4ERR_BADSLOT = 10053isize,
    NFS4ERR_COMPLETE_ALREADY = 10054isize,
    NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055isize,
    NFS4ERR_DELEG_ALREADY_WANTED = 10056isize,
    NFS4ERR_BACK_CHAN_BUSY = 10057isize,
    NFS4ERR_LAYOUTTRYLATER = 10058isize,
    NFS4ERR_LAYOUTUNAVAILABLE = 10059isize,
    NFS4ERR_NOMATCHING_LAYOUT = 10060isize,
    NFS4ERR_RECALLCONFLICT = 10061isize,
    NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062isize,
    NFS4ERR_SEQ_MISORDERED = 10063isize,
    NFS4ERR_SEQUENCE_POS = 10064isize,
    NFS4ERR_REQ_TOO_BIG = 10065isize,
    NFS4ERR_REP_TOO_BIG = 10066isize,
    NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067isize,
    NFS4ERR_RETRY_UNCACHED_REP = 10068isize,
    NFS4ERR_UNSAFE_COMPOUND = 10069isize,
    NFS4ERR_TOO_MANY_OPS = 10070isize,
    NFS4ERR_OP_NOT_IN_SESSION = 10071isize,
    NFS4ERR_HASH_ALG_UNSUPP = 10072isize,
    NFS4ERR_CONN_BINDING_NOT_ENFORCED = 10073isize,
    NFS4ERR_CLIENTID_BUSY = 10074isize,
    NFS4ERR_PNFS_IO_HOLE = 10075isize,
    NFS4ERR_SEQ_FALSE_RETRY = 10076isize,
    NFS4ERR_BAD_HIGH_SLOT = 10077isize,
    NFS4ERR_DEADSESSION = 10078isize,
    NFS4ERR_ENCR_ALG_UNSUPP = 10079isize,
    NFS4ERR_PNFS_NO_LAYOUT = 10080isize,
    NFS4ERR_NOT_ONLY_OP = 10081isize,
    NFS4ERR_WRONG_CRED = 10082isize,
    NFS4ERR_WRONG_TYPE = 10083isize,
    NFS4ERR_DIRDELEG_UNAVAIL = 10084isize,
    NFS4ERR_REJECT_DELEG = 10085isize,
    NFS4ERR_RETURNCONFLICT = 10086isize,
    NFS4ERR_NOXATTR = 10095isize,
    NFS4ERR_XATTR2BIG = 10096isize,
    NFS4ERR_AWSFILE_BYPASS = 100001isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct nfstime4 {
    pub seconds: int64_t,
    pub nseconds: uint32_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct nfsv4_1_file_layout4 {
    pub nfl_deviceid: deviceid4,
    pub nfl_util: nfl_util4,
    pub nfl_first_stripe_index: uint32_t,
    pub nfl_pattern_offset: offset4,
    pub nfl_fh_list: Vec<nfs_fh4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct nfsv4_1_file_layout_ds_addr4 {
    pub nflda_stripe_indices: Vec<uint32_t>,
    pub nflda_multipath_ds_list: Vec<multipath_list4>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct nfsv4_1_file_layouthint4 {
    pub nflh_care: uint32_t,
    pub nflh_util: nfl_util4,
    pub nflh_stripe_count: count4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notify4 {
    pub notify_mask: bitmap4,
    pub notify_vals: notifylist4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notify_add4 {
    pub nad_old_entry: Vec<notify_remove4>,
    pub nad_new_entry: notify_entry4,
    pub nad_new_entry_cookie: Vec<nfs_cookie4>,
    pub nad_prev_entry: Vec<prev_entry4>,
    pub nad_last_entry: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notify_attr4 {
    pub na_changed_entry: notify_entry4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct notify_deviceid_change4 {
    pub ndc_layouttype: layouttype4,
    pub ndc_deviceid: deviceid4,
    pub ndc_immediate: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct notify_deviceid_delete4 {
    pub ndd_layouttype: layouttype4,
    pub ndd_deviceid: deviceid4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum notify_deviceid_type4 {
    NOTIFY_DEVICEID4_CHANGE = 1isize,
    NOTIFY_DEVICEID4_DELETE = 2isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notify_entry4 {
    pub ne_file: component4,
    pub ne_attrs: fattr4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notify_remove4 {
    pub nrm_old_entry: notify_entry4,
    pub nrm_old_entry_cookie: nfs_cookie4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notify_rename4 {
    pub nrn_old_entry: notify_remove4,
    pub nrn_new_entry: notify_add4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum notify_type4 {
    NOTIFY4_CHANGE_CHILD_ATTRS = 0isize,
    NOTIFY4_CHANGE_DIR_ATTRS = 1isize,
    NOTIFY4_REMOVE_ENTRY = 2isize,
    NOTIFY4_ADD_ENTRY = 3isize,
    NOTIFY4_RENAME_ENTRY = 4isize,
    NOTIFY4_CHANGE_COOKIE_VERIFIER = 5isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct notify_verifier4 {
    pub nv_old_cookieverf: verifier4,
    pub nv_new_cookieverf: verifier4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct notifylist4(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum open_claim4 {
    CLAIM_NULL(component4),
    CLAIM_PREVIOUS(open_delegation_type4),
    CLAIM_DELEGATE_CUR(open_claim_delegate_cur4),
    CLAIM_DELEGATE_PREV(component4),
    CLAIM_FH,
    CLAIM_DELEG_PREV_FH,
    CLAIM_DELEG_CUR_FH(stateid4),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct open_claim_delegate_cur4 {
    pub delegate_stateid: stateid4,
    pub file: component4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum open_claim_type4 {
    CLAIM_NULL = 0isize,
    CLAIM_PREVIOUS = 1isize,
    CLAIM_DELEGATE_CUR = 2isize,
    CLAIM_DELEGATE_PREV = 3isize,
    CLAIM_FH = 4isize,
    CLAIM_DELEG_CUR_FH = 5isize,
    CLAIM_DELEG_PREV_FH = 6isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum open_delegation4 {
    OPEN_DELEGATE_NONE,
    OPEN_DELEGATE_READ(open_read_delegation4),
    OPEN_DELEGATE_WRITE(open_write_delegation4),
    OPEN_DELEGATE_NONE_EXT(open_none_delegation4),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum open_delegation_type4 {
    OPEN_DELEGATE_NONE = 0isize,
    OPEN_DELEGATE_READ = 1isize,
    OPEN_DELEGATE_WRITE = 2isize,
    OPEN_DELEGATE_NONE_EXT = 3isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum open_none_delegation4 {
    WND4_CONTENTION(bool),
    WND4_RESOURCE(bool),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct open_read_delegation4 {
    pub stateid: stateid4,
    pub recall: bool,
    pub permissions: nfsace4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct open_to_lock_owner4 {
    pub open_seqid: seqid4,
    pub open_stateid: stateid4,
    pub lock_seqid: seqid4,
    pub lock_owner: lock_owner4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct open_write_delegation4 {
    pub stateid: stateid4,
    pub recall: bool,
    pub space_limit: nfs_space_limit4,
    pub permissions: nfsace4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum openflag4 {
    OPEN4_CREATE(createhow4),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum opentype4 {
    OPEN4_NOCREATE = 0isize,
    OPEN4_CREATE = 1isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct pathname4(pub Vec<component4>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct prev_entry4 {
    pub pe_prev_entry: notify_entry4,
    pub pe_prev_entry_cookie: nfs_cookie4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct referring_call4 {
    pub rc_sequenceid: sequenceid4,
    pub rc_slotid: slotid4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct referring_call_list4 {
    pub rcl_sessionid: sessionid4,
    pub rcl_referring_calls: Vec<referring_call4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct retention_get4 {
    pub rg_duration: uint64_t,
    pub rg_begin_time: Vec<nfstime4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct retention_set4 {
    pub rs_enable: bool,
    pub rs_duration: Vec<uint64_t>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum rpc_gss_svc_t {
    RPC_GSS_SVC_NONE = 1isize,
    RPC_GSS_SVC_INTEGRITY = 2isize,
    RPC_GSS_SVC_PRIVACY = 3isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct rpcsec_gss_info {
    pub oid: sec_oid4,
    pub qop: qop4,
    pub service: rpc_gss_svc_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct sec_oid4(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum secinfo4 {
    RPCSEC_GSS(rpcsec_gss_info),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum secinfo_style4 {
    SECINFO_STYLE4_CURRENT_FH = 0isize,
    SECINFO_STYLE4_PARENT = 1isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct server_owner4 {
    pub so_minor_id: uint64_t,
    pub so_major_id: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct sessionid4(pub [u8; NFS4_SESSIONID_SIZE as usize]);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum settime4 {
    SET_TO_CLIENT_TIME4(nfstime4),
    default,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum setxattr_option4 {
    SETXATTR4_EITHER = 0isize,
    SETXATTR4_CREATE = 1isize,
    SETXATTR4_REPLACE = 2isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct specdata4 {
    pub specdata1: uint32_t,
    pub specdata2: uint32_t,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ssa_digest_input4 {
    pub sdi_seqargs: SEQUENCE4args,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ssr_digest_input4 {
    pub sdi_seqres: SEQUENCE4res,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ssv_mic_plain_tkn4 {
    pub smpt_ssv_seq: uint32_t,
    pub smpt_orig_plain: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ssv_mic_tkn4 {
    pub smt_ssv_seq: uint32_t,
    pub smt_hmac: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ssv_prot_info4 {
    pub spi_ops: state_protect_ops4,
    pub spi_hash_alg: uint32_t,
    pub spi_encr_alg: uint32_t,
    pub spi_ssv_len: uint32_t,
    pub spi_window: uint32_t,
    pub spi_handles: Vec<gsshandle4_t>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ssv_seal_cipher_tkn4 {
    pub ssct_ssv_seq: uint32_t,
    pub ssct_iv: Vec<u8>,
    pub ssct_encr_data: Vec<u8>,
    pub ssct_hmac: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ssv_seal_plain_tkn4 {
    pub sspt_confounder: Vec<u8>,
    pub sspt_ssv_seq: uint32_t,
    pub sspt_orig_plain: Vec<u8>,
    pub sspt_pad: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ssv_sp_parms4 {
    pub ssp_ops: state_protect_ops4,
    pub ssp_hash_algs: Vec<sec_oid4>,
    pub ssp_encr_algs: Vec<sec_oid4>,
    pub ssp_window: uint32_t,
    pub ssp_num_gss_handles: uint32_t,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ssv_subkey4 {
    SSV4_SUBKEY_MIC_I2T = 1isize,
    SSV4_SUBKEY_MIC_T2I = 2isize,
    SSV4_SUBKEY_SEAL_I2T = 3isize,
    SSV4_SUBKEY_SEAL_T2I = 4isize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum stable_how4 {
    UNSTABLE4 = 0isize,
    DATA_SYNC4 = 1isize,
    FILE_SYNC4 = 2isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct state_owner4 {
    pub clientid: clientid4,
    pub owner: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum state_protect4_a {
    SP4_NONE,
    SP4_MACH_CRED(state_protect_ops4),
    SP4_SSV(ssv_sp_parms4),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum state_protect4_r {
    SP4_NONE,
    SP4_MACH_CRED(state_protect_ops4),
    SP4_SSV(ssv_prot_info4),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum state_protect_how4 {
    SP4_NONE = 0isize,
    SP4_MACH_CRED = 1isize,
    SP4_SSV = 2isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct state_protect_ops4 {
    pub spo_must_enforce: bitmap4,
    pub spo_must_allow: bitmap4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct stateid4 {
    pub seqid: uint32_t,
    pub other: [u8; 12i64 as usize],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct threshold_item4 {
    pub thi_layout_type: layouttype4,
    pub thi_hintset: bitmap4,
    pub thi_hintlist: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum time_how4 {
    SET_TO_SERVER_TIME4 = 0isize,
    SET_TO_CLIENT_TIME4 = 1isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct utf8string(pub Vec<u8>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct verifier4(pub [u8; NFS4_VERIFIER_SIZE as usize]);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum why_no_delegation4 {
    WND4_NOT_WANTED = 0isize,
    WND4_CONTENTION = 1isize,
    WND4_RESOURCE = 2isize,
    WND4_NOT_SUPP_FTYPE = 3isize,
    WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4isize,
    WND4_NOT_SUPP_UPGRADE = 5isize,
    WND4_NOT_SUPP_DOWNGRADE = 6isize,
    WND4_CANCELED = 7isize,
    WND4_IS_DIR = 8isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct xattrvalue4(pub Vec<u8>);

pub type AWSFILE_READ_BYPASS4args = READ4args;

pub type CB_RECALLABLE_OBJ_AVAIL4args = CB_RECALL_ANY4args;

pub type SECINFO_NO_NAME4args = secinfo_style4;

pub type SECINFO_NO_NAME4res = SECINFO4res;

pub type aceflag4 = uint32_t;

pub type acemask4 = uint32_t;

pub type acetype4 = uint32_t;

pub type aclflag4 = uint32_t;

pub type attr_notice4 = nfstime4;

pub type changeid4 = uint64_t;

pub type clientaddr4 = netaddr4;

pub type clientid4 = uint64_t;

pub type component4 = utf8str_cs;

pub type count4 = uint32_t;

pub type fattr4_absent = bool;

pub type fattr4_aclsupport = uint32_t;

pub type fattr4_archive = bool;

pub type fattr4_cansettime = bool;

pub type fattr4_case_insensitive = bool;

pub type fattr4_case_preserving = bool;

pub type fattr4_change = changeid4;

pub type fattr4_chown_restricted = bool;

pub type fattr4_dacl = nfsacl41;

pub type fattr4_dir_notif_delay = nfstime4;

pub type fattr4_dirent_notif_delay = nfstime4;

pub type fattr4_fh_expire_type = uint32_t;

pub type fattr4_filehandle = nfs_fh4;

pub type fattr4_fileid = uint64_t;

pub type fattr4_files_avail = uint64_t;

pub type fattr4_files_free = uint64_t;

pub type fattr4_files_total = uint64_t;

pub type fattr4_fs_charset_cap4 = fs_charset_cap4;

pub type fattr4_fs_locations = fs_locations4;

pub type fattr4_fs_locations_info = fs_locations_info4;

pub type fattr4_fs_status = fs4_status;

pub type fattr4_fsid = fsid4;

pub type fattr4_hidden = bool;

pub type fattr4_homogeneous = bool;

pub type fattr4_layout_alignment = uint32_t;

pub type fattr4_layout_blksize = uint32_t;

pub type fattr4_layout_hint = layouthint4;

pub type fattr4_lease_time = nfs_lease4;

pub type fattr4_link_support = bool;

pub type fattr4_maxfilesize = uint64_t;

pub type fattr4_maxlink = uint32_t;

pub type fattr4_maxname = uint32_t;

pub type fattr4_maxread = uint64_t;

pub type fattr4_maxwrite = uint64_t;

pub type fattr4_mdsthreshold = mdsthreshold4;

pub type fattr4_mimetype = utf8str_cs;

pub type fattr4_mode = mode4;

pub type fattr4_mode_set_masked = mode_masked4;

pub type fattr4_mounted_on_fileid = uint64_t;

pub type fattr4_named_attr = bool;

pub type fattr4_no_trunc = bool;

pub type fattr4_numlinks = uint32_t;

pub type fattr4_owner = utf8str_mixed;

pub type fattr4_owner_group = utf8str_mixed;

pub type fattr4_quota_avail_hard = uint64_t;

pub type fattr4_quota_avail_soft = uint64_t;

pub type fattr4_quota_used = uint64_t;

pub type fattr4_rawdev = specdata4;

pub type fattr4_rdattr_error = nfsstat4;

pub type fattr4_retentevt_get = retention_get4;

pub type fattr4_retentevt_set = retention_set4;

pub type fattr4_retention_get = retention_get4;

pub type fattr4_retention_hold = uint64_t;

pub type fattr4_retention_set = retention_set4;

pub type fattr4_sacl = nfsacl41;

pub type fattr4_size = uint64_t;

pub type fattr4_space_avail = uint64_t;

pub type fattr4_space_free = uint64_t;

pub type fattr4_space_total = uint64_t;

pub type fattr4_space_used = uint64_t;

pub type fattr4_suppattr_exclcreat = bitmap4;

pub type fattr4_supported_attrs = bitmap4;

pub type fattr4_symlink_support = bool;

pub type fattr4_system = bool;

pub type fattr4_time_access = nfstime4;

pub type fattr4_time_access_set = settime4;

pub type fattr4_time_backup = nfstime4;

pub type fattr4_time_create = nfstime4;

pub type fattr4_time_delta = nfstime4;

pub type fattr4_time_metadata = nfstime4;

pub type fattr4_time_modify = nfstime4;

pub type fattr4_time_modify_set = settime4;

pub type fattr4_type = nfs_ftype4;

pub type fattr4_unique_handles = bool;

pub type fattr4_xattr_support = bool;

pub type fs_charset_cap4 = uint32_t;

pub type int32_t = i32;

pub type int64_t = i64;

pub type length4 = uint64_t;

pub type linktext4 = utf8str_cs;

pub type lock_owner4 = state_owner4;

pub type mode4 = uint32_t;

pub type nfl_util4 = uint32_t;

pub type nfs_cookie4 = uint64_t;

pub type nfs_lease4 = uint32_t;

pub type offset4 = uint64_t;

pub type open_owner4 = state_owner4;

pub type qop4 = uint32_t;

pub type seqid4 = uint32_t;

pub type sequenceid4 = uint32_t;

pub type slotid4 = uint32_t;

pub type threshold4_read_iosize = length4;

pub type threshold4_read_size = length4;

pub type threshold4_write_iosize = length4;

pub type threshold4_write_size = length4;

pub type uint32_t = u32;

pub type uint64_t = u64;

pub type utf8str_cis = utf8string;

pub type utf8str_cs = utf8string;

pub type utf8str_mixed = utf8string;

pub type xattrkey4 = component4;

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ACCESS4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.access.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ACCESS4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &ACCESS4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &ACCESS4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ACCESS4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.supported.pack(out)? + self.access.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for AWSFILE_READ_BYPASS4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &AWSFILE_READ_BYPASS4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(ref val) => {
                (nfsstat4::NFS4ERR_AWSFILE_BYPASS as i32).pack(out)? + val.pack(out)?
            }
            &AWSFILE_READ_BYPASS4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for AWSFILE_READ_BYPASS4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.filehandle.pack(out)?
            + self.data_locator.pack(out)?
            + self.file_size.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for BACKCHANNEL_CTL4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.bca_cb_program.pack(out)?
            + xdr_codec::pack_flex(&self.bca_sec_parms, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for BACKCHANNEL_CTL4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.bcr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for BIND_CONN_TO_SESSION4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.bctsa_sessid.pack(out)?
            + self.bctsa_dir.pack(out)?
            + self.bctsa_use_conn_in_rdma_mode.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for BIND_CONN_TO_SESSION4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &BIND_CONN_TO_SESSION4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &BIND_CONN_TO_SESSION4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for BIND_CONN_TO_SESSION4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.bctsr_sessid.pack(out)?
            + self.bctsr_dir.pack(out)?
            + self.bctsr_use_conn_in_rdma_mode.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_AWSFILE_HEARTBEAT4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clientid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_AWSFILE_HEARTBEAT4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.hb_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_COMPOUND4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.tag.pack(out)?
            + self.minorversion.pack(out)?
            + self.callback_ident.pack(out)?
            + xdr_codec::pack_flex(&self.argarray, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_COMPOUND4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)?
            + self.tag.pack(out)?
            + xdr_codec::pack_flex(&self.resarray, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_GETATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fh.pack(out)? + self.attr_request.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_GETATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &CB_GETATTR4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &CB_GETATTR4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_GETATTR4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.obj_attributes.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_ILLEGAL4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_LAYOUTRECALL4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clora_type.pack(out)?
            + self.clora_iomode.pack(out)?
            + self.clora_changed.pack(out)?
            + self.clora_recall.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_LAYOUTRECALL4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clorr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_NOTIFY4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cna_stateid.pack(out)?
            + self.cna_fh.pack(out)?
            + xdr_codec::pack_flex(&self.cna_changes, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_NOTIFY4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cnr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_NOTIFY_DEVICEID4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.cnda_changes, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_NOTIFY_DEVICEID4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cndr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_NOTIFY_LOCK4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cnla_fh.pack(out)? + self.cnla_lock_owner.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_NOTIFY_LOCK4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cnlr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_PUSH_DELEG4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cpda_fh.pack(out)? + self.cpda_delegation.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_PUSH_DELEG4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cpdr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALL4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)? + self.truncate.pack(out)? + self.fh.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALL4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALLABLE_OBJ_AVAIL4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.croa_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALL_ANY4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.craa_objects_to_keep.pack(out)? + self.craa_type_mask.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALL_ANY4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.crar_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALL_SLOT4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rsa_target_highest_slotid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_RECALL_SLOT4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rsr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_SEQUENCE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.csa_sessionid.pack(out)?
            + self.csa_sequenceid.pack(out)?
            + self.csa_slotid.pack(out)?
            + self.csa_highest_slotid.pack(out)?
            + self.csa_cachethis.pack(out)?
            + xdr_codec::pack_flex(&self.csa_referring_call_lists, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_SEQUENCE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &CB_SEQUENCE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &CB_SEQUENCE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_SEQUENCE4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.csr_sessionid.pack(out)?
            + self.csr_sequenceid.pack(out)?
            + self.csr_slotid.pack(out)?
            + self.csr_highest_slotid.pack(out)?
            + self.csr_target_highest_slotid.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_WANTS_CANCELLED4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cwca_contended_wants_cancelled.pack(out)?
            + self.cwca_resourced_wants_cancelled.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CB_WANTS_CANCELLED4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cwcr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CLOSE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.seqid.pack(out)? + self.open_stateid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CLOSE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &CLOSE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &CLOSE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for COMMIT4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.offset.pack(out)? + self.count.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for COMMIT4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &COMMIT4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &COMMIT4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for COMMIT4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.writeverf.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for COMPOUND4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.tag.pack(out)?
            + self.minorversion.pack(out)?
            + xdr_codec::pack_flex(&self.argarray, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for COMPOUND4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)?
            + self.tag.pack(out)?
            + xdr_codec::pack_flex(&self.resarray, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CREATE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.objtype.pack(out)? + self.objname.pack(out)? + self.createattrs.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CREATE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &CREATE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &CREATE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CREATE4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cinfo.pack(out)? + self.attrset.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CREATE_SESSION4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.csa_clientid.pack(out)?
            + self.csa_sequence.pack(out)?
            + self.csa_flags.pack(out)?
            + self.csa_fore_chan_attrs.pack(out)?
            + self.csa_back_chan_attrs.pack(out)?
            + self.csa_cb_program.pack(out)?
            + xdr_codec::pack_flex(&self.csa_sec_parms, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CREATE_SESSION4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &CREATE_SESSION4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &CREATE_SESSION4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for CREATE_SESSION4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.csr_sessionid.pack(out)?
            + self.csr_sequence.pack(out)?
            + self.csr_flags.pack(out)?
            + self.csr_fore_chan_attrs.pack(out)?
            + self.csr_back_chan_attrs.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DELEGPURGE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clientid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DELEGPURGE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DELEGRETURN4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.deleg_stateid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DELEGRETURN4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DESTROY_CLIENTID4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.dca_clientid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DESTROY_CLIENTID4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.dcr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DESTROY_SESSION4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.dsa_sessionid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for DESTROY_SESSION4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.dsr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for EXCHANGE_ID4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.eia_clientowner.pack(out)?
            + self.eia_flags.pack(out)?
            + self.eia_state_protect.pack(out)?
            + xdr_codec::pack_flex(&self.eia_client_impl_id, Some(1i64 as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for EXCHANGE_ID4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &EXCHANGE_ID4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &EXCHANGE_ID4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for EXCHANGE_ID4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.eir_clientid.pack(out)?
            + self.eir_sequenceid.pack(out)?
            + self.eir_flags.pack(out)?
            + self.eir_state_protect.pack(out)?
            + self.eir_server_owner.pack(out)?
            + xdr_codec::pack_opaque_flex(
                &self.eir_server_scope,
                Some(NFS4_OPAQUE_LIMIT as usize),
                out,
            )?
            + xdr_codec::pack_flex(&self.eir_server_impl_id, Some(1i64 as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for FREE_STATEID4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fsa_stateid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for FREE_STATEID4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fsr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.attr_request.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GETATTR4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GETATTR4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETATTR4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.obj_attributes.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETDEVICEINFO4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gdia_device_id.pack(out)?
            + self.gdia_layout_type.pack(out)?
            + self.gdia_maxcount.pack(out)?
            + self.gdia_notify_types.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETDEVICEINFO4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GETDEVICEINFO4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GETDEVICEINFO4res::NFS4ERR_TOOSMALL(ref val) => {
                (nfsstat4::NFS4ERR_TOOSMALL as i32).pack(out)? + val.pack(out)?
            }
            &GETDEVICEINFO4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETDEVICEINFO4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gdir_device_addr.pack(out)? + self.gdir_notification.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETDEVICELIST4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gdla_layout_type.pack(out)?
            + self.gdla_maxdevices.pack(out)?
            + self.gdla_cookie.pack(out)?
            + self.gdla_cookieverf.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETDEVICELIST4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GETDEVICELIST4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GETDEVICELIST4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETDEVICELIST4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gdlr_cookie.pack(out)?
            + self.gdlr_cookieverf.pack(out)?
            + xdr_codec::pack_flex(&self.gdlr_deviceid_list, None, out)?
            + self.gdlr_eof.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETFH4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GETFH4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GETFH4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETFH4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.object.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETXATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gxa_name.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GETXATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GETXATTR4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GETXATTR4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GET_DIR_DELEGATION4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gdda_signal_deleg_avail.pack(out)?
            + self.gdda_notification_types.pack(out)?
            + self.gdda_child_attr_delay.pack(out)?
            + self.gdda_dir_attr_delay.pack(out)?
            + self.gdda_child_attributes.pack(out)?
            + self.gdda_dir_attributes.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GET_DIR_DELEGATION4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GET_DIR_DELEGATION4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GET_DIR_DELEGATION4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GET_DIR_DELEGATION4res_non_fatal {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &GET_DIR_DELEGATION4res_non_fatal::GDD4_OK(ref val) => {
                (gddrnf4_status::GDD4_OK as i32).pack(out)? + val.pack(out)?
            }
            &GET_DIR_DELEGATION4res_non_fatal::GDD4_UNAVAIL(ref val) => {
                (gddrnf4_status::GDD4_UNAVAIL as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for GET_DIR_DELEGATION4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gddr_cookieverf.pack(out)?
            + self.gddr_stateid.pack(out)?
            + self.gddr_notification.pack(out)?
            + self.gddr_child_attributes.pack(out)?
            + self.gddr_dir_attributes.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ILLEGAL4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTCOMMIT4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.loca_offset.pack(out)?
            + self.loca_length.pack(out)?
            + self.loca_reclaim.pack(out)?
            + self.loca_stateid.pack(out)?
            + self.loca_last_write_offset.pack(out)?
            + self.loca_time_modify.pack(out)?
            + self.loca_layoutupdate.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTCOMMIT4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LAYOUTCOMMIT4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &LAYOUTCOMMIT4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTCOMMIT4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.locr_newsize.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTGET4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.loga_signal_layout_avail.pack(out)?
            + self.loga_layout_type.pack(out)?
            + self.loga_iomode.pack(out)?
            + self.loga_offset.pack(out)?
            + self.loga_length.pack(out)?
            + self.loga_minlength.pack(out)?
            + self.loga_stateid.pack(out)?
            + self.loga_maxcount.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTGET4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LAYOUTGET4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &LAYOUTGET4res::NFS4ERR_LAYOUTTRYLATER(ref val) => {
                (nfsstat4::NFS4ERR_LAYOUTTRYLATER as i32).pack(out)? + val.pack(out)?
            }
            &LAYOUTGET4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTGET4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.logr_return_on_close.pack(out)?
            + self.logr_stateid.pack(out)?
            + xdr_codec::pack_flex(&self.logr_layout, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTRETURN4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lora_reclaim.pack(out)?
            + self.lora_layout_type.pack(out)?
            + self.lora_iomode.pack(out)?
            + self.lora_layoutreturn.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LAYOUTRETURN4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LAYOUTRETURN4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &LAYOUTRETURN4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LINK4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.newname.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LINK4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LINK4res::NFS4_OK(ref val) => (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?,
            &LINK4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LINK4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cinfo.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LISTXATTRS4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lxa_cookie.pack(out)? + self.lxa_maxcount.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LISTXATTRS4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LISTXATTRS4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &LISTXATTRS4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LISTXATTRS4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lxr_cookie.pack(out)?
            + xdr_codec::pack_flex(&self.lxr_names, None, out)?
            + self.lxr_eof.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCK4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.locktype.pack(out)?
            + self.reclaim.pack(out)?
            + self.offset.pack(out)?
            + self.length.pack(out)?
            + self.locker.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCK4denied {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.offset.pack(out)?
            + self.length.pack(out)?
            + self.locktype.pack(out)?
            + self.owner.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCK4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LOCK4res::NFS4_OK(ref val) => (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?,
            &LOCK4res::NFS4ERR_DENIED(ref val) => {
                (nfsstat4::NFS4ERR_DENIED as i32).pack(out)? + val.pack(out)?
            }
            &LOCK4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCK4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lock_stateid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCKT4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.locktype.pack(out)?
            + self.offset.pack(out)?
            + self.length.pack(out)?
            + self.owner.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCKT4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LOCKT4res::NFS4ERR_DENIED(ref val) => {
                (nfsstat4::NFS4ERR_DENIED as i32).pack(out)? + val.pack(out)?
            }
            &LOCKT4res::NFS4_OK => (nfsstat4::NFS4_OK as i32).pack(out)?,
            &LOCKT4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCKU4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.locktype.pack(out)?
            + self.seqid.pack(out)?
            + self.lock_stateid.pack(out)?
            + self.offset.pack(out)?
            + self.length.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOCKU4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &LOCKU4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &LOCKU4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOOKUP4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.objname.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOOKUP4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for LOOKUPP4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for NVERIFY4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.obj_attributes.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for NVERIFY4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.seqid.pack(out)?
            + self.share_access.pack(out)?
            + self.share_deny.pack(out)?
            + self.owner.pack(out)?
            + self.openhow.pack(out)?
            + self.claim.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &OPEN4res::NFS4_OK(ref val) => (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?,
            &OPEN4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)?
            + self.cinfo.pack(out)?
            + self.rflags.pack(out)?
            + self.attrset.pack(out)?
            + self.delegation.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPENATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.createdir.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPENATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN_CONFIRM4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.open_stateid.pack(out)? + self.seqid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN_CONFIRM4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &OPEN_CONFIRM4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &OPEN_CONFIRM4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN_CONFIRM4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.open_stateid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN_DOWNGRADE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.open_stateid.pack(out)?
            + self.seqid.pack(out)?
            + self.share_access.pack(out)?
            + self.share_deny.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN_DOWNGRADE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &OPEN_DOWNGRADE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &OPEN_DOWNGRADE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for OPEN_DOWNGRADE4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.open_stateid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for PUTFH4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.object.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for PUTFH4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for PUTPUBFH4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for PUTROOTFH4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READ4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)? + self.offset.pack(out)? + self.count.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READ4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &READ4res::NFS4_OK(ref val) => (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?,
            &READ4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READ4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        match self.data {
            DataPayload::Data(ref data) => {
                Ok(self.eof.pack(out)? + xdr_codec::pack_opaque_flex(&data, None, out)? + 0)
            }
            _ => Err(xdr_codec::Error::invalidcase(-1)),
        }
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READDIR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cookie.pack(out)?
            + self.cookieverf.pack(out)?
            + self.dircount.pack(out)?
            + self.maxcount.pack(out)?
            + self.attr_request.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READDIR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &READDIR4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &READDIR4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READDIR4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cookieverf.pack(out)? + self.reply.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READLINK4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &READLINK4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &READLINK4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for READLINK4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.link.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RECLAIM_COMPLETE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rca_one_fs.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RECLAIM_COMPLETE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rcr_status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RELEASE_LOCKOWNER4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lock_owner.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RELEASE_LOCKOWNER4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for REMOVE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.target.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for REMOVE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &REMOVE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &REMOVE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for REMOVE4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cinfo.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for REMOVEXATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rxa_name.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for REMOVEXATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &REMOVEXATTR4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &REMOVEXATTR4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RENAME4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.oldname.pack(out)? + self.newname.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RENAME4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &RENAME4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &RENAME4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RENAME4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.source_cinfo.pack(out)? + self.target_cinfo.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RENEW4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clientid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RENEW4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for RESTOREFH4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SAVEFH4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SECINFO4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.name.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SECINFO4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &SECINFO4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &SECINFO4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SECINFO4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SEQUENCE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.sa_sessionid.pack(out)?
            + self.sa_sequenceid.pack(out)?
            + self.sa_slotid.pack(out)?
            + self.sa_highest_slotid.pack(out)?
            + self.sa_cachethis.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SEQUENCE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &SEQUENCE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &SEQUENCE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SEQUENCE4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.sr_sessionid.pack(out)?
            + self.sr_sequenceid.pack(out)?
            + self.sr_slotid.pack(out)?
            + self.sr_highest_slotid.pack(out)?
            + self.sr_target_highest_slotid.pack(out)?
            + self.sr_status_flags.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)? + self.obj_attributes.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + self.attrsset.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETCLIENTID4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.client.pack(out)? + self.callback.pack(out)? + self.callback_ident.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETCLIENTID4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &SETCLIENTID4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &SETCLIENTID4res::NFS4ERR_CLID_INUSE(ref val) => {
                (nfsstat4::NFS4ERR_CLID_INUSE as i32).pack(out)? + val.pack(out)?
            }
            &SETCLIENTID4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETCLIENTID4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clientid.pack(out)? + self.setclientid_confirm.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETCLIENTID_CONFIRM4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clientid.pack(out)? + self.setclientid_confirm.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETCLIENTID_CONFIRM4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETXATTR4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.sxa_option.pack(out)? + self.sxa_key.pack(out)? + self.sxa_value.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SETXATTR4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &SETXATTR4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &SETXATTR4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SET_SSV4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.ssa_ssv, None, out)?
            + xdr_codec::pack_opaque_flex(&self.ssa_digest, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SET_SSV4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &SET_SSV4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &SET_SSV4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for SET_SSV4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.ssr_digest, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for TEST_STATEID4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.ts_stateids, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for TEST_STATEID4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &TEST_STATEID4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &TEST_STATEID4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for TEST_STATEID4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.tsr_status_codes, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for VERIFY4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.obj_attributes.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for VERIFY4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for WANT_DELEGATION4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.wda_want.pack(out)? + self.wda_claim.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for WANT_DELEGATION4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &WANT_DELEGATION4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &WANT_DELEGATION4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for WRITE4args {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)?
            + self.offset.pack(out)?
            + self.stable.pack(out)?
            + match self.data {
                DataPayload::Data(ref data) => xdr_codec::pack_opaque_flex(data, None, out)?,
                DataPayload::DataRef(ref data) => {
                    return Err(xdr_codec::Error::invalidcase(-1));
                }
            })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for WRITE4res {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &WRITE4res::NFS4_OK(ref val) => {
                (nfsstat4::NFS4_OK as i32).pack(out)? + val.pack(out)?
            }
            &WRITE4res::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for WRITE4resok {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.count.pack(out)? + self.committed.pack(out)? + self.writeverf.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for attrlist4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for auth_flavor4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for authsys_parms {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stamp.pack(out)?
            + self.machinename.pack(out)?
            + self.uid.pack(out)?
            + self.gid.pack(out)?
            + xdr_codec::pack_flex(&self.gids, Some(16i64 as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for awsfile_bypass_data_locator {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.bucket_name, None, out)?
            + xdr_codec::pack_opaque_flex(&self.s3_key, None, out)?
            + xdr_codec::pack_opaque_flex(&self.etag, None, out)?
            + xdr_codec::pack_opaque_flex(&self.version_id, None, out)?
            + self.offset.pack(out)?
            + self.count.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for bitmap4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for boolflag {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for callback_sec_parms4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &callback_sec_parms4::AUTH_NONE => (auth_flavor4::AUTH_NONE as i32).pack(out)?,
            &callback_sec_parms4::AUTH_SYS(ref val) => {
                (auth_flavor4::AUTH_SYS as i32).pack(out)? + val.pack(out)?
            }
            &callback_sec_parms4::RPCSEC_GSS(ref val) => {
                (auth_flavor4::RPCSEC_GSS as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for cb_client4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cb_program.pack(out)? + self.cb_location.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for change_info4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.atomic.pack(out)? + self.before.pack(out)? + self.after.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for change_policy4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cp_major.pack(out)? + self.cp_minor.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for channel_attrs4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.ca_headerpadsize.pack(out)?
            + self.ca_maxrequestsize.pack(out)?
            + self.ca_maxresponsesize.pack(out)?
            + self.ca_maxresponsesize_cached.pack(out)?
            + self.ca_maxoperations.pack(out)?
            + self.ca_maxrequests.pack(out)?
            + xdr_codec::pack_flex(&self.ca_rdma_ird, Some(1i64 as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for channel_dir_from_client4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for channel_dir_from_server4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for client_owner4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.co_verifier.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.co_ownerid, Some(NFS4_OPAQUE_LIMIT as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for createhow4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &createhow4::UNCHECKED4(ref val) => {
                (createmode4::UNCHECKED4 as i32).pack(out)? + val.pack(out)?
            }
            &createhow4::GUARDED4(ref val) => {
                (createmode4::GUARDED4 as i32).pack(out)? + val.pack(out)?
            }
            &createhow4::EXCLUSIVE4(ref val) => {
                (createmode4::EXCLUSIVE4 as i32).pack(out)? + val.pack(out)?
            }
            &createhow4::EXCLUSIVE4_1(ref val) => {
                (createmode4::EXCLUSIVE4_1 as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for createmode4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for createtype4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &createtype4::NF4LNK(ref val) => {
                (nfs_ftype4::NF4LNK as i32).pack(out)? + val.pack(out)?
            }
            &createtype4::NF4BLK(ref val) => {
                (nfs_ftype4::NF4BLK as i32).pack(out)? + val.pack(out)?
            }
            &createtype4::NF4CHR(ref val) => {
                (nfs_ftype4::NF4CHR as i32).pack(out)? + val.pack(out)?
            }
            &createtype4::NF4SOCK => (nfs_ftype4::NF4SOCK as i32).pack(out)?,
            &createtype4::NF4FIFO => (nfs_ftype4::NF4FIFO as i32).pack(out)?,
            &createtype4::NF4DIR => (nfs_ftype4::NF4DIR as i32).pack(out)?,
            &createtype4::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for creatverfattr {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cva_verf.pack(out)? + self.cva_attrs.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for deleg_claim4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &deleg_claim4::CLAIM_FH => (open_claim_type4::CLAIM_FH as i32).pack(out)?,
            &deleg_claim4::CLAIM_DELEG_PREV_FH => {
                (open_claim_type4::CLAIM_DELEG_PREV_FH as i32).pack(out)?
            }
            &deleg_claim4::CLAIM_PREVIOUS(ref val) => {
                (open_claim_type4::CLAIM_PREVIOUS as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for device_addr4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.da_layout_type.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.da_addr_body, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for deviceid4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_array(
            &self.0[..],
            self.0.len(),
            out,
        )?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for dirlist4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.entries.pack(out)? + self.eof.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for entry4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.cookie.pack(out)?
            + self.name.pack(out)?
            + self.attrs.pack(out)?
            + self.nextentry.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for exist_lock_owner4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lock_stateid.pack(out)? + self.lock_seqid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fattr4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.attrmask.pack(out)? + self.attr_vals.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fattr4_acl {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fattr4_fs_layout_types {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fattr4_layout_types {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for filelayout_hint_care4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs4_status {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fss_absent.pack(out)?
            + self.fss_type.pack(out)?
            + self.fss_source.pack(out)?
            + self.fss_current.pack(out)?
            + self.fss_age.pack(out)?
            + self.fss_version.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs4_status_type {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs_location4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.server, None, out)? + self.rootpath.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs_locations4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fs_root.pack(out)? + xdr_codec::pack_flex(&self.locations, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs_locations_info4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fli_flags.pack(out)?
            + self.fli_valid_for.pack(out)?
            + self.fli_fs_root.pack(out)?
            + xdr_codec::pack_flex(&self.fli_items, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs_locations_item4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.fli_entries, None, out)? + self.fli_rootpath.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fs_locations_server4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.fls_currency.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.fls_info, None, out)?
            + self.fls_server.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for fsid4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.major.pack(out)? + self.minor.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for gddrnf4_status {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for gss_cb_handles4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.gcbp_service.pack(out)?
            + self.gcbp_handle_from_server.pack(out)?
            + self.gcbp_handle_from_client.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for gsshandle4_t {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layout4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lo_offset.pack(out)?
            + self.lo_length.pack(out)?
            + self.lo_iomode.pack(out)?
            + self.lo_content.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layout_content4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.loc_type.pack(out)? + xdr_codec::pack_opaque_flex(&self.loc_body, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layouthint4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.loh_type.pack(out)? + xdr_codec::pack_opaque_flex(&self.loh_body, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutiomode4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutrecall4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &layoutrecall4::LAYOUTRECALL4_FILE(ref val) => {
                (layoutrecall_type4::LAYOUTRECALL4_FILE as i32).pack(out)? + val.pack(out)?
            }
            &layoutrecall4::LAYOUTRECALL4_FSID(ref val) => {
                (layoutrecall_type4::LAYOUTRECALL4_FSID as i32).pack(out)? + val.pack(out)?
            }
            &layoutrecall4::LAYOUTRECALL4_ALL => {
                (layoutrecall_type4::LAYOUTRECALL4_ALL as i32).pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutrecall_file4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lor_fh.pack(out)?
            + self.lor_offset.pack(out)?
            + self.lor_length.pack(out)?
            + self.lor_stateid.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutrecall_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutreturn4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &layoutreturn4::LAYOUTRETURN4_FILE(ref val) => {
                (layoutreturn_type4::LAYOUTRETURN4_FILE as i32).pack(out)? + val.pack(out)?
            }
            &layoutreturn4::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutreturn_file4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lrf_offset.pack(out)?
            + self.lrf_length.pack(out)?
            + self.lrf_stateid.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.lrf_body, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutreturn_stateid {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &layoutreturn_stateid::TRUE(ref val) => {
                (boolflag::TRUE as i32).pack(out)? + val.pack(out)?
            }
            &layoutreturn_stateid::FALSE => (boolflag::FALSE as i32).pack(out)?,
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutreturn_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layouttype4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for layoutupdate4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.lou_type.pack(out)? + xdr_codec::pack_opaque_flex(&self.lou_body, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for limit_by4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for locker4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &locker4::TRUE(ref val) => (boolflag::TRUE as i32).pack(out)? + val.pack(out)?,
            &locker4::FALSE(ref val) => (boolflag::FALSE as i32).pack(out)? + val.pack(out)?,
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for mdsthreshold4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.mth_hints, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for mode_masked4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.mm_value_to_set.pack(out)? + self.mm_mask_bits.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for multipath_list4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for netaddr4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_string(&self.na_r_netid, None, out)?
            + xdr_codec::pack_string(&self.na_r_addr, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for newoffset4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &newoffset4::TRUE(ref val) => (boolflag::TRUE as i32).pack(out)? + val.pack(out)?,
            &newoffset4::FALSE => (boolflag::FALSE as i32).pack(out)?,
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for newsize4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &newsize4::TRUE(ref val) => (boolflag::TRUE as i32).pack(out)? + val.pack(out)?,
            &newsize4::FALSE => (boolflag::FALSE as i32).pack(out)?,
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for newtime4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &newtime4::TRUE(ref val) => (boolflag::TRUE as i32).pack(out)? + val.pack(out)?,
            &newtime4::FALSE => (boolflag::FALSE as i32).pack(out)?,
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_argop4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &nfs_argop4::OP_ACCESS(ref val) => {
                (nfs_opnum4::OP_ACCESS as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_CLOSE(ref val) => {
                (nfs_opnum4::OP_CLOSE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_COMMIT(ref val) => {
                (nfs_opnum4::OP_COMMIT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_CREATE(ref val) => {
                (nfs_opnum4::OP_CREATE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_DELEGPURGE(ref val) => {
                (nfs_opnum4::OP_DELEGPURGE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_DELEGRETURN(ref val) => {
                (nfs_opnum4::OP_DELEGRETURN as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_GETATTR(ref val) => {
                (nfs_opnum4::OP_GETATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_GETFH => (nfs_opnum4::OP_GETFH as i32).pack(out)?,
            &nfs_argop4::OP_LINK(ref val) => {
                (nfs_opnum4::OP_LINK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LOCK(ref val) => {
                (nfs_opnum4::OP_LOCK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LOCKT(ref val) => {
                (nfs_opnum4::OP_LOCKT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LOCKU(ref val) => {
                (nfs_opnum4::OP_LOCKU as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LOOKUP(ref val) => {
                (nfs_opnum4::OP_LOOKUP as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LOOKUPP => (nfs_opnum4::OP_LOOKUPP as i32).pack(out)?,
            &nfs_argop4::OP_NVERIFY(ref val) => {
                (nfs_opnum4::OP_NVERIFY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_OPEN(ref val) => {
                (nfs_opnum4::OP_OPEN as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_OPENATTR(ref val) => {
                (nfs_opnum4::OP_OPENATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_OPEN_CONFIRM(ref val) => {
                (nfs_opnum4::OP_OPEN_CONFIRM as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_OPEN_DOWNGRADE(ref val) => {
                (nfs_opnum4::OP_OPEN_DOWNGRADE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_PUTFH(ref val) => {
                (nfs_opnum4::OP_PUTFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_PUTPUBFH => (nfs_opnum4::OP_PUTPUBFH as i32).pack(out)?,
            &nfs_argop4::OP_PUTROOTFH => (nfs_opnum4::OP_PUTROOTFH as i32).pack(out)?,
            &nfs_argop4::OP_READ(ref val) => {
                (nfs_opnum4::OP_READ as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_READDIR(ref val) => {
                (nfs_opnum4::OP_READDIR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_READLINK => (nfs_opnum4::OP_READLINK as i32).pack(out)?,
            &nfs_argop4::OP_REMOVE(ref val) => {
                (nfs_opnum4::OP_REMOVE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_RENAME(ref val) => {
                (nfs_opnum4::OP_RENAME as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_RENEW(ref val) => {
                (nfs_opnum4::OP_RENEW as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_RESTOREFH => (nfs_opnum4::OP_RESTOREFH as i32).pack(out)?,
            &nfs_argop4::OP_SAVEFH => (nfs_opnum4::OP_SAVEFH as i32).pack(out)?,
            &nfs_argop4::OP_SECINFO(ref val) => {
                (nfs_opnum4::OP_SECINFO as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SETATTR(ref val) => {
                (nfs_opnum4::OP_SETATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SETCLIENTID(ref val) => {
                (nfs_opnum4::OP_SETCLIENTID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SETCLIENTID_CONFIRM(ref val) => {
                (nfs_opnum4::OP_SETCLIENTID_CONFIRM as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_VERIFY(ref val) => {
                (nfs_opnum4::OP_VERIFY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_WRITE(ref val) => {
                (nfs_opnum4::OP_WRITE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_RELEASE_LOCKOWNER(ref val) => {
                (nfs_opnum4::OP_RELEASE_LOCKOWNER as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_BACKCHANNEL_CTL(ref val) => {
                (nfs_opnum4::OP_BACKCHANNEL_CTL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_BIND_CONN_TO_SESSION(ref val) => {
                (nfs_opnum4::OP_BIND_CONN_TO_SESSION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_EXCHANGE_ID(ref val) => {
                (nfs_opnum4::OP_EXCHANGE_ID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_CREATE_SESSION(ref val) => {
                (nfs_opnum4::OP_CREATE_SESSION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_DESTROY_SESSION(ref val) => {
                (nfs_opnum4::OP_DESTROY_SESSION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_FREE_STATEID(ref val) => {
                (nfs_opnum4::OP_FREE_STATEID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_GET_DIR_DELEGATION(ref val) => {
                (nfs_opnum4::OP_GET_DIR_DELEGATION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_GETDEVICEINFO(ref val) => {
                (nfs_opnum4::OP_GETDEVICEINFO as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_GETDEVICELIST(ref val) => {
                (nfs_opnum4::OP_GETDEVICELIST as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LAYOUTCOMMIT(ref val) => {
                (nfs_opnum4::OP_LAYOUTCOMMIT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LAYOUTGET(ref val) => {
                (nfs_opnum4::OP_LAYOUTGET as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LAYOUTRETURN(ref val) => {
                (nfs_opnum4::OP_LAYOUTRETURN as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SECINFO_NO_NAME(ref val) => {
                (nfs_opnum4::OP_SECINFO_NO_NAME as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SEQUENCE(ref val) => {
                (nfs_opnum4::OP_SEQUENCE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SET_SSV(ref val) => {
                (nfs_opnum4::OP_SET_SSV as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_TEST_STATEID(ref val) => {
                (nfs_opnum4::OP_TEST_STATEID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_WANT_DELEGATION(ref val) => {
                (nfs_opnum4::OP_WANT_DELEGATION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_DESTROY_CLIENTID(ref val) => {
                (nfs_opnum4::OP_DESTROY_CLIENTID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_RECLAIM_COMPLETE(ref val) => {
                (nfs_opnum4::OP_RECLAIM_COMPLETE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_GETXATTR(ref val) => {
                (nfs_opnum4::OP_GETXATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_SETXATTR(ref val) => {
                (nfs_opnum4::OP_SETXATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_LISTXATTRS(ref val) => {
                (nfs_opnum4::OP_LISTXATTRS as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_REMOVEXATTR(ref val) => {
                (nfs_opnum4::OP_REMOVEXATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_argop4::OP_ILLEGAL => (nfs_opnum4::OP_ILLEGAL as i32).pack(out)?,
            &nfs_argop4::OP_AWSFILE_READ_BYPASS(ref val) => {
                (nfs_opnum4::OP_AWSFILE_READ_BYPASS as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_cb_argop4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &nfs_cb_argop4::OP_CB_GETATTR(ref val) => {
                (nfs_cb_opnum4::OP_CB_GETATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_RECALL(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_LAYOUTRECALL(ref val) => {
                (nfs_cb_opnum4::OP_CB_LAYOUTRECALL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_NOTIFY(ref val) => {
                (nfs_cb_opnum4::OP_CB_NOTIFY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_PUSH_DELEG(ref val) => {
                (nfs_cb_opnum4::OP_CB_PUSH_DELEG as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_RECALL_ANY(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALL_ANY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_RECALLABLE_OBJ_AVAIL(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALLABLE_OBJ_AVAIL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_RECALL_SLOT(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALL_SLOT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_SEQUENCE(ref val) => {
                (nfs_cb_opnum4::OP_CB_SEQUENCE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_WANTS_CANCELLED(ref val) => {
                (nfs_cb_opnum4::OP_CB_WANTS_CANCELLED as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_NOTIFY_LOCK(ref val) => {
                (nfs_cb_opnum4::OP_CB_NOTIFY_LOCK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_NOTIFY_DEVICEID(ref val) => {
                (nfs_cb_opnum4::OP_CB_NOTIFY_DEVICEID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_argop4::OP_CB_ILLEGAL => (nfs_cb_opnum4::OP_CB_ILLEGAL as i32).pack(out)?,
            &nfs_cb_argop4::OP_CB_AWSFILE_HEARTBEAT(ref val) => {
                (nfs_cb_opnum4::OP_CB_AWSFILE_HEARTBEAT as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_cb_opnum4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_cb_resop4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &nfs_cb_resop4::OP_CB_GETATTR(ref val) => {
                (nfs_cb_opnum4::OP_CB_GETATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_RECALL(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_LAYOUTRECALL(ref val) => {
                (nfs_cb_opnum4::OP_CB_LAYOUTRECALL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_NOTIFY(ref val) => {
                (nfs_cb_opnum4::OP_CB_NOTIFY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_PUSH_DELEG(ref val) => {
                (nfs_cb_opnum4::OP_CB_PUSH_DELEG as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_RECALL_ANY(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALL_ANY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_RECALLABLE_OBJ_AVAIL(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALLABLE_OBJ_AVAIL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_RECALL_SLOT(ref val) => {
                (nfs_cb_opnum4::OP_CB_RECALL_SLOT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_SEQUENCE(ref val) => {
                (nfs_cb_opnum4::OP_CB_SEQUENCE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_WANTS_CANCELLED(ref val) => {
                (nfs_cb_opnum4::OP_CB_WANTS_CANCELLED as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_NOTIFY_LOCK(ref val) => {
                (nfs_cb_opnum4::OP_CB_NOTIFY_LOCK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_NOTIFY_DEVICEID(ref val) => {
                (nfs_cb_opnum4::OP_CB_NOTIFY_DEVICEID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_ILLEGAL(ref val) => {
                (nfs_cb_opnum4::OP_CB_ILLEGAL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_cb_resop4::OP_CB_AWSFILE_HEARTBEAT(ref val) => {
                (nfs_cb_opnum4::OP_CB_AWSFILE_HEARTBEAT as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_client_id4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.verifier.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.id, Some(NFS4_OPAQUE_LIMIT as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_fh4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(
            &self.0,
            Some(NFS4_FHSIZE as usize),
            out,
        )?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_ftype4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_impl_id4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.nii_domain.pack(out)? + self.nii_name.pack(out)? + self.nii_date.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_lock_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_modified_limit4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.num_blocks.pack(out)? + self.bytes_per_block.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_opnum4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_resop4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &nfs_resop4::OP_ACCESS(ref val) => {
                (nfs_opnum4::OP_ACCESS as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_CLOSE(ref val) => {
                (nfs_opnum4::OP_CLOSE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_COMMIT(ref val) => {
                (nfs_opnum4::OP_COMMIT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_CREATE(ref val) => {
                (nfs_opnum4::OP_CREATE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_DELEGPURGE(ref val) => {
                (nfs_opnum4::OP_DELEGPURGE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_DELEGRETURN(ref val) => {
                (nfs_opnum4::OP_DELEGRETURN as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_GETATTR(ref val) => {
                (nfs_opnum4::OP_GETATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_GETFH(ref val) => {
                (nfs_opnum4::OP_GETFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LINK(ref val) => {
                (nfs_opnum4::OP_LINK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LOCK(ref val) => {
                (nfs_opnum4::OP_LOCK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LOCKT(ref val) => {
                (nfs_opnum4::OP_LOCKT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LOCKU(ref val) => {
                (nfs_opnum4::OP_LOCKU as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LOOKUP(ref val) => {
                (nfs_opnum4::OP_LOOKUP as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LOOKUPP(ref val) => {
                (nfs_opnum4::OP_LOOKUPP as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_NVERIFY(ref val) => {
                (nfs_opnum4::OP_NVERIFY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_OPEN(ref val) => {
                (nfs_opnum4::OP_OPEN as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_OPENATTR(ref val) => {
                (nfs_opnum4::OP_OPENATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_OPEN_CONFIRM(ref val) => {
                (nfs_opnum4::OP_OPEN_CONFIRM as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_OPEN_DOWNGRADE(ref val) => {
                (nfs_opnum4::OP_OPEN_DOWNGRADE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_PUTFH(ref val) => {
                (nfs_opnum4::OP_PUTFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_PUTPUBFH(ref val) => {
                (nfs_opnum4::OP_PUTPUBFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_PUTROOTFH(ref val) => {
                (nfs_opnum4::OP_PUTROOTFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_READ(ref val) => {
                (nfs_opnum4::OP_READ as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_READDIR(ref val) => {
                (nfs_opnum4::OP_READDIR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_READLINK(ref val) => {
                (nfs_opnum4::OP_READLINK as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_REMOVE(ref val) => {
                (nfs_opnum4::OP_REMOVE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_RENAME(ref val) => {
                (nfs_opnum4::OP_RENAME as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_RENEW(ref val) => {
                (nfs_opnum4::OP_RENEW as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_RESTOREFH(ref val) => {
                (nfs_opnum4::OP_RESTOREFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SAVEFH(ref val) => {
                (nfs_opnum4::OP_SAVEFH as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SECINFO(ref val) => {
                (nfs_opnum4::OP_SECINFO as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SETATTR(ref val) => {
                (nfs_opnum4::OP_SETATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SETCLIENTID(ref val) => {
                (nfs_opnum4::OP_SETCLIENTID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SETCLIENTID_CONFIRM(ref val) => {
                (nfs_opnum4::OP_SETCLIENTID_CONFIRM as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_VERIFY(ref val) => {
                (nfs_opnum4::OP_VERIFY as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_WRITE(ref val) => {
                (nfs_opnum4::OP_WRITE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_RELEASE_LOCKOWNER(ref val) => {
                (nfs_opnum4::OP_RELEASE_LOCKOWNER as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_BACKCHANNEL_CTL(ref val) => {
                (nfs_opnum4::OP_BACKCHANNEL_CTL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_BIND_CONN_TO_SESSION(ref val) => {
                (nfs_opnum4::OP_BIND_CONN_TO_SESSION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_EXCHANGE_ID(ref val) => {
                (nfs_opnum4::OP_EXCHANGE_ID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_CREATE_SESSION(ref val) => {
                (nfs_opnum4::OP_CREATE_SESSION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_DESTROY_SESSION(ref val) => {
                (nfs_opnum4::OP_DESTROY_SESSION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_FREE_STATEID(ref val) => {
                (nfs_opnum4::OP_FREE_STATEID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_GET_DIR_DELEGATION(ref val) => {
                (nfs_opnum4::OP_GET_DIR_DELEGATION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_GETDEVICEINFO(ref val) => {
                (nfs_opnum4::OP_GETDEVICEINFO as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_GETDEVICELIST(ref val) => {
                (nfs_opnum4::OP_GETDEVICELIST as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LAYOUTCOMMIT(ref val) => {
                (nfs_opnum4::OP_LAYOUTCOMMIT as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LAYOUTGET(ref val) => {
                (nfs_opnum4::OP_LAYOUTGET as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LAYOUTRETURN(ref val) => {
                (nfs_opnum4::OP_LAYOUTRETURN as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SECINFO_NO_NAME(ref val) => {
                (nfs_opnum4::OP_SECINFO_NO_NAME as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SEQUENCE(ref val) => {
                (nfs_opnum4::OP_SEQUENCE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SET_SSV(ref val) => {
                (nfs_opnum4::OP_SET_SSV as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_TEST_STATEID(ref val) => {
                (nfs_opnum4::OP_TEST_STATEID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_WANT_DELEGATION(ref val) => {
                (nfs_opnum4::OP_WANT_DELEGATION as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_DESTROY_CLIENTID(ref val) => {
                (nfs_opnum4::OP_DESTROY_CLIENTID as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_RECLAIM_COMPLETE(ref val) => {
                (nfs_opnum4::OP_RECLAIM_COMPLETE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_GETXATTR(ref val) => {
                (nfs_opnum4::OP_GETXATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_SETXATTR(ref val) => {
                (nfs_opnum4::OP_SETXATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_LISTXATTRS(ref val) => {
                (nfs_opnum4::OP_LISTXATTRS as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_REMOVEXATTR(ref val) => {
                (nfs_opnum4::OP_REMOVEXATTR as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_ILLEGAL(ref val) => {
                (nfs_opnum4::OP_ILLEGAL as i32).pack(out)? + val.pack(out)?
            }
            &nfs_resop4::OP_AWSFILE_READ_BYPASS(ref val) => {
                (nfs_opnum4::OP_AWSFILE_READ_BYPASS as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfs_space_limit4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &nfs_space_limit4::NFS_LIMIT_SIZE(ref val) => {
                (limit_by4::NFS_LIMIT_SIZE as i32).pack(out)? + val.pack(out)?
            }
            &nfs_space_limit4::NFS_LIMIT_BLOCKS(ref val) => {
                (limit_by4::NFS_LIMIT_BLOCKS as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfsace4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.type_.pack(out)?
            + self.flag.pack(out)?
            + self.access_mask.pack(out)?
            + self.who.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfsacl41 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.na41_flag.pack(out)? + xdr_codec::pack_flex(&self.na41_aces, None, out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfsstat4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfstime4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.seconds.pack(out)? + self.nseconds.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfsv4_1_file_layout4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.nfl_deviceid.pack(out)?
            + self.nfl_util.pack(out)?
            + self.nfl_first_stripe_index.pack(out)?
            + self.nfl_pattern_offset.pack(out)?
            + xdr_codec::pack_flex(&self.nfl_fh_list, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfsv4_1_file_layout_ds_addr4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.nflda_stripe_indices, None, out)?
            + xdr_codec::pack_flex(&self.nflda_multipath_ds_list, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for nfsv4_1_file_layouthint4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.nflh_care.pack(out)?
            + self.nflh_util.pack(out)?
            + self.nflh_stripe_count.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.notify_mask.pack(out)? + self.notify_vals.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_add4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(
            xdr_codec::pack_flex(&self.nad_old_entry, Some(1i64 as usize), out)?
                + self.nad_new_entry.pack(out)?
                + xdr_codec::pack_flex(&self.nad_new_entry_cookie, Some(1i64 as usize), out)?
                + xdr_codec::pack_flex(&self.nad_prev_entry, Some(1i64 as usize), out)?
                + self.nad_last_entry.pack(out)?
                + 0,
        )
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_attr4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.na_changed_entry.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_deviceid_change4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.ndc_layouttype.pack(out)?
            + self.ndc_deviceid.pack(out)?
            + self.ndc_immediate.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_deviceid_delete4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.ndd_layouttype.pack(out)? + self.ndd_deviceid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_deviceid_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_entry4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.ne_file.pack(out)? + self.ne_attrs.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_remove4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.nrm_old_entry.pack(out)? + self.nrm_old_entry_cookie.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_rename4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.nrn_old_entry.pack(out)? + self.nrn_new_entry.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notify_verifier4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.nv_old_cookieverf.pack(out)? + self.nv_new_cookieverf.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for notifylist4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_claim4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &open_claim4::CLAIM_NULL(ref val) => {
                (open_claim_type4::CLAIM_NULL as i32).pack(out)? + val.pack(out)?
            }
            &open_claim4::CLAIM_PREVIOUS(ref val) => {
                (open_claim_type4::CLAIM_PREVIOUS as i32).pack(out)? + val.pack(out)?
            }
            &open_claim4::CLAIM_DELEGATE_CUR(ref val) => {
                (open_claim_type4::CLAIM_DELEGATE_CUR as i32).pack(out)? + val.pack(out)?
            }
            &open_claim4::CLAIM_DELEGATE_PREV(ref val) => {
                (open_claim_type4::CLAIM_DELEGATE_PREV as i32).pack(out)? + val.pack(out)?
            }
            &open_claim4::CLAIM_FH => (open_claim_type4::CLAIM_FH as i32).pack(out)?,
            &open_claim4::CLAIM_DELEG_PREV_FH => {
                (open_claim_type4::CLAIM_DELEG_PREV_FH as i32).pack(out)?
            }
            &open_claim4::CLAIM_DELEG_CUR_FH(ref val) => {
                (open_claim_type4::CLAIM_DELEG_CUR_FH as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_claim_delegate_cur4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.delegate_stateid.pack(out)? + self.file.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_claim_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_delegation4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &open_delegation4::OPEN_DELEGATE_NONE => {
                (open_delegation_type4::OPEN_DELEGATE_NONE as i32).pack(out)?
            }
            &open_delegation4::OPEN_DELEGATE_READ(ref val) => {
                (open_delegation_type4::OPEN_DELEGATE_READ as i32).pack(out)? + val.pack(out)?
            }
            &open_delegation4::OPEN_DELEGATE_WRITE(ref val) => {
                (open_delegation_type4::OPEN_DELEGATE_WRITE as i32).pack(out)? + val.pack(out)?
            }
            &open_delegation4::OPEN_DELEGATE_NONE_EXT(ref val) => {
                (open_delegation_type4::OPEN_DELEGATE_NONE_EXT as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_delegation_type4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_none_delegation4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &open_none_delegation4::WND4_CONTENTION(ref val) => {
                (why_no_delegation4::WND4_CONTENTION as i32).pack(out)? + val.pack(out)?
            }
            &open_none_delegation4::WND4_RESOURCE(ref val) => {
                (why_no_delegation4::WND4_RESOURCE as i32).pack(out)? + val.pack(out)?
            }
            &open_none_delegation4::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_read_delegation4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)? + self.recall.pack(out)? + self.permissions.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_to_lock_owner4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.open_seqid.pack(out)?
            + self.open_stateid.pack(out)?
            + self.lock_seqid.pack(out)?
            + self.lock_owner.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for open_write_delegation4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.stateid.pack(out)?
            + self.recall.pack(out)?
            + self.space_limit.pack(out)?
            + self.permissions.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for openflag4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &openflag4::OPEN4_CREATE(ref val) => {
                (opentype4::OPEN4_CREATE as i32).pack(out)? + val.pack(out)?
            }
            &openflag4::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for opentype4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for pathname4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for prev_entry4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.pe_prev_entry.pack(out)? + self.pe_prev_entry_cookie.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for referring_call4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rc_sequenceid.pack(out)? + self.rc_slotid.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for referring_call_list4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rcl_sessionid.pack(out)?
            + xdr_codec::pack_flex(&self.rcl_referring_calls, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for retention_get4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rg_duration.pack(out)?
            + xdr_codec::pack_flex(&self.rg_begin_time, Some(1i64 as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for retention_set4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.rs_enable.pack(out)?
            + xdr_codec::pack_flex(&self.rs_duration, Some(1i64 as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for rpc_gss_svc_t {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for rpcsec_gss_info {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.oid.pack(out)? + self.qop.pack(out)? + self.service.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for sec_oid4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for secinfo4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &secinfo4::RPCSEC_GSS(ref val) => {
                (auth_flavor4::RPCSEC_GSS as i32).pack(out)? + val.pack(out)?
            }
            &secinfo4::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for secinfo_style4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for server_owner4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.so_minor_id.pack(out)?
            + xdr_codec::pack_opaque_flex(
                &self.so_major_id,
                Some(NFS4_OPAQUE_LIMIT as usize),
                out,
            )?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for sessionid4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_array(
            &self.0[..],
            self.0.len(),
            out,
        )?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for settime4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &settime4::SET_TO_CLIENT_TIME4(ref val) => {
                (time_how4::SET_TO_CLIENT_TIME4 as i32).pack(out)? + val.pack(out)?
            }
            &settime4::default => return Err(xdr_codec::Error::invalidcase(-1)),
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for setxattr_option4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for specdata4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.specdata1.pack(out)? + self.specdata2.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssa_digest_input4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.sdi_seqargs.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssr_digest_input4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.sdi_seqres.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_mic_plain_tkn4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.smpt_ssv_seq.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.smpt_orig_plain, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_mic_tkn4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.smt_ssv_seq.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.smt_hmac, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_prot_info4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.spi_ops.pack(out)?
            + self.spi_hash_alg.pack(out)?
            + self.spi_encr_alg.pack(out)?
            + self.spi_ssv_len.pack(out)?
            + self.spi_window.pack(out)?
            + xdr_codec::pack_flex(&self.spi_handles, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_seal_cipher_tkn4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.ssct_ssv_seq.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.ssct_iv, None, out)?
            + xdr_codec::pack_opaque_flex(&self.ssct_encr_data, None, out)?
            + xdr_codec::pack_opaque_flex(&self.ssct_hmac, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_seal_plain_tkn4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(
            xdr_codec::pack_opaque_flex(&self.sspt_confounder, None, out)?
                + self.sspt_ssv_seq.pack(out)?
                + xdr_codec::pack_opaque_flex(&self.sspt_orig_plain, None, out)?
                + xdr_codec::pack_opaque_flex(&self.sspt_pad, None, out)?
                + 0,
        )
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_sp_parms4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.ssp_ops.pack(out)?
            + xdr_codec::pack_flex(&self.ssp_hash_algs, None, out)?
            + xdr_codec::pack_flex(&self.ssp_encr_algs, None, out)?
            + self.ssp_window.pack(out)?
            + self.ssp_num_gss_handles.pack(out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for ssv_subkey4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for stable_how4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for state_owner4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.clientid.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.owner, Some(NFS4_OPAQUE_LIMIT as usize), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for state_protect4_a {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &state_protect4_a::SP4_NONE => (state_protect_how4::SP4_NONE as i32).pack(out)?,
            &state_protect4_a::SP4_MACH_CRED(ref val) => {
                (state_protect_how4::SP4_MACH_CRED as i32).pack(out)? + val.pack(out)?
            }
            &state_protect4_a::SP4_SSV(ref val) => {
                (state_protect_how4::SP4_SSV as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for state_protect4_r {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(match self {
            &state_protect4_r::SP4_NONE => (state_protect_how4::SP4_NONE as i32).pack(out)?,
            &state_protect4_r::SP4_MACH_CRED(ref val) => {
                (state_protect_how4::SP4_MACH_CRED as i32).pack(out)? + val.pack(out)?
            }
            &state_protect4_r::SP4_SSV(ref val) => {
                (state_protect_how4::SP4_SSV as i32).pack(out)? + val.pack(out)?
            }
        })
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for state_protect_how4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for state_protect_ops4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.spo_must_enforce.pack(out)? + self.spo_must_allow.pack(out)? + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for stateid4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.seqid.pack(out)?
            + xdr_codec::pack_opaque_array(&self.other[..], self.other.len(), out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for threshold_item4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(self.thi_layout_type.pack(out)?
            + self.thi_hintset.pack(out)?
            + xdr_codec::pack_opaque_flex(&self.thi_hintlist, None, out)?
            + 0)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for time_how4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for utf8string {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.0, None, out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for verifier4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_array(
            &self.0[..],
            self.0.len(),
            out,
        )?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for why_no_delegation4 {
    #[inline]
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok((*self as i32).pack(out)?)
    }
}

impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for xattrvalue4 {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(xdr_codec::pack_opaque_flex(&self.0, None, out)?)
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ACCESS4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ACCESS4args, usize)> {
        let mut sz = 0;
        Ok((
            ACCESS4args {
                access: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ACCESS4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ACCESS4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => ACCESS4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => ACCESS4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ACCESS4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ACCESS4resok, usize)> {
        let mut sz = 0;
        Ok((
            ACCESS4resok {
                supported: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                access: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for AWSFILE_READ_BYPASS4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(AWSFILE_READ_BYPASS4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => AWSFILE_READ_BYPASS4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (100001i32 as i32) => AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => AWSFILE_READ_BYPASS4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for AWSFILE_READ_BYPASS4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(AWSFILE_READ_BYPASS4resok, usize)> {
        let mut sz = 0;
        Ok((
            AWSFILE_READ_BYPASS4resok {
                filehandle: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                data_locator: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                file_size: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for BACKCHANNEL_CTL4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(BACKCHANNEL_CTL4args, usize)> {
        let mut sz = 0;
        Ok((
            BACKCHANNEL_CTL4args {
                bca_cb_program: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                bca_sec_parms: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for BACKCHANNEL_CTL4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(BACKCHANNEL_CTL4res, usize)> {
        let mut sz = 0;
        Ok((
            BACKCHANNEL_CTL4res {
                bcr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for BIND_CONN_TO_SESSION4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(BIND_CONN_TO_SESSION4args, usize)> {
        let mut sz = 0;
        Ok((
            BIND_CONN_TO_SESSION4args {
                bctsa_sessid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                bctsa_dir: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                bctsa_use_conn_in_rdma_mode: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for BIND_CONN_TO_SESSION4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(BIND_CONN_TO_SESSION4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => BIND_CONN_TO_SESSION4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => BIND_CONN_TO_SESSION4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for BIND_CONN_TO_SESSION4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(BIND_CONN_TO_SESSION4resok, usize)> {
        let mut sz = 0;
        Ok((
            BIND_CONN_TO_SESSION4resok {
                bctsr_sessid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                bctsr_dir: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                bctsr_use_conn_in_rdma_mode: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_AWSFILE_HEARTBEAT4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_AWSFILE_HEARTBEAT4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_AWSFILE_HEARTBEAT4args {
                clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_AWSFILE_HEARTBEAT4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_AWSFILE_HEARTBEAT4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_AWSFILE_HEARTBEAT4res {
                hb_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_COMPOUND4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_COMPOUND4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_COMPOUND4args {
                tag: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                minorversion: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                callback_ident: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                argarray: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_COMPOUND4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_COMPOUND4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_COMPOUND4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                tag: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                resarray: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_GETATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_GETATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_GETATTR4args {
                fh: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attr_request: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_GETATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_GETATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => CB_GETATTR4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => CB_GETATTR4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_GETATTR4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_GETATTR4resok, usize)> {
        let mut sz = 0;
        Ok((
            CB_GETATTR4resok {
                obj_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_ILLEGAL4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_ILLEGAL4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_ILLEGAL4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_LAYOUTRECALL4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_LAYOUTRECALL4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_LAYOUTRECALL4args {
                clora_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                clora_iomode: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                clora_changed: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                clora_recall: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_LAYOUTRECALL4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_LAYOUTRECALL4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_LAYOUTRECALL4res {
                clorr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_NOTIFY4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_NOTIFY4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_NOTIFY4args {
                cna_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cna_fh: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cna_changes: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_NOTIFY4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_NOTIFY4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_NOTIFY4res {
                cnr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_NOTIFY_DEVICEID4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_NOTIFY_DEVICEID4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_NOTIFY_DEVICEID4args {
                cnda_changes: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_NOTIFY_DEVICEID4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_NOTIFY_DEVICEID4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_NOTIFY_DEVICEID4res {
                cndr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_NOTIFY_LOCK4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_NOTIFY_LOCK4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_NOTIFY_LOCK4args {
                cnla_fh: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cnla_lock_owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_NOTIFY_LOCK4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_NOTIFY_LOCK4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_NOTIFY_LOCK4res {
                cnlr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_PUSH_DELEG4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_PUSH_DELEG4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_PUSH_DELEG4args {
                cpda_fh: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cpda_delegation: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_PUSH_DELEG4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_PUSH_DELEG4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_PUSH_DELEG4res {
                cpdr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALL4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALL4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALL4args {
                stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                truncate: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fh: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALL4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALL4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALL4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALLABLE_OBJ_AVAIL4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALLABLE_OBJ_AVAIL4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALLABLE_OBJ_AVAIL4res {
                croa_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALL_ANY4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALL_ANY4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALL_ANY4args {
                craa_objects_to_keep: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                craa_type_mask: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALL_ANY4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALL_ANY4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALL_ANY4res {
                crar_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALL_SLOT4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALL_SLOT4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALL_SLOT4args {
                rsa_target_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_RECALL_SLOT4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_RECALL_SLOT4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_RECALL_SLOT4res {
                rsr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_SEQUENCE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_SEQUENCE4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_SEQUENCE4args {
                csa_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_sequenceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_cachethis: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_referring_call_lists: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_SEQUENCE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_SEQUENCE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => CB_SEQUENCE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => CB_SEQUENCE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_SEQUENCE4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_SEQUENCE4resok, usize)> {
        let mut sz = 0;
        Ok((
            CB_SEQUENCE4resok {
                csr_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_sequenceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_target_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_WANTS_CANCELLED4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_WANTS_CANCELLED4args, usize)> {
        let mut sz = 0;
        Ok((
            CB_WANTS_CANCELLED4args {
                cwca_contended_wants_cancelled: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cwca_resourced_wants_cancelled: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CB_WANTS_CANCELLED4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CB_WANTS_CANCELLED4res, usize)> {
        let mut sz = 0;
        Ok((
            CB_WANTS_CANCELLED4res {
                cwcr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CLOSE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CLOSE4args, usize)> {
        let mut sz = 0;
        Ok((
            CLOSE4args {
                seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                open_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CLOSE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CLOSE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => CLOSE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => CLOSE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for COMMIT4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(COMMIT4args, usize)> {
        let mut sz = 0;
        Ok((
            COMMIT4args {
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                count: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for COMMIT4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(COMMIT4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => COMMIT4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => COMMIT4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for COMMIT4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(COMMIT4resok, usize)> {
        let mut sz = 0;
        Ok((
            COMMIT4resok {
                writeverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for COMPOUND4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(COMPOUND4args, usize)> {
        let mut sz = 0;
        Ok((
            COMPOUND4args {
                tag: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                minorversion: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                argarray: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for COMPOUND4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(COMPOUND4res, usize)> {
        let mut sz = 0;
        Ok((
            COMPOUND4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                tag: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                resarray: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CREATE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CREATE4args, usize)> {
        let mut sz = 0;
        Ok((
            CREATE4args {
                objtype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                objname: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                createattrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CREATE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CREATE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => CREATE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => CREATE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CREATE4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CREATE4resok, usize)> {
        let mut sz = 0;
        Ok((
            CREATE4resok {
                cinfo: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attrset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CREATE_SESSION4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CREATE_SESSION4args, usize)> {
        let mut sz = 0;
        Ok((
            CREATE_SESSION4args {
                csa_clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_sequence: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_flags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_fore_chan_attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_back_chan_attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_cb_program: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csa_sec_parms: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CREATE_SESSION4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CREATE_SESSION4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => CREATE_SESSION4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => CREATE_SESSION4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for CREATE_SESSION4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(CREATE_SESSION4resok, usize)> {
        let mut sz = 0;
        Ok((
            CREATE_SESSION4resok {
                csr_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_sequence: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_flags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_fore_chan_attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                csr_back_chan_attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DELEGPURGE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DELEGPURGE4args, usize)> {
        let mut sz = 0;
        Ok((
            DELEGPURGE4args {
                clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DELEGPURGE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DELEGPURGE4res, usize)> {
        let mut sz = 0;
        Ok((
            DELEGPURGE4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DELEGRETURN4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DELEGRETURN4args, usize)> {
        let mut sz = 0;
        Ok((
            DELEGRETURN4args {
                deleg_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DELEGRETURN4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DELEGRETURN4res, usize)> {
        let mut sz = 0;
        Ok((
            DELEGRETURN4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DESTROY_CLIENTID4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DESTROY_CLIENTID4args, usize)> {
        let mut sz = 0;
        Ok((
            DESTROY_CLIENTID4args {
                dca_clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DESTROY_CLIENTID4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DESTROY_CLIENTID4res, usize)> {
        let mut sz = 0;
        Ok((
            DESTROY_CLIENTID4res {
                dcr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DESTROY_SESSION4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DESTROY_SESSION4args, usize)> {
        let mut sz = 0;
        Ok((
            DESTROY_SESSION4args {
                dsa_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for DESTROY_SESSION4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(DESTROY_SESSION4res, usize)> {
        let mut sz = 0;
        Ok((
            DESTROY_SESSION4res {
                dsr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for EXCHANGE_ID4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(EXCHANGE_ID4args, usize)> {
        let mut sz = 0;
        Ok((
            EXCHANGE_ID4args {
                eia_clientowner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eia_flags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eia_state_protect: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eia_client_impl_id: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for EXCHANGE_ID4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(EXCHANGE_ID4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => EXCHANGE_ID4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => EXCHANGE_ID4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for EXCHANGE_ID4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(EXCHANGE_ID4resok, usize)> {
        let mut sz = 0;
        Ok((
            EXCHANGE_ID4resok {
                eir_clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eir_sequenceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eir_flags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eir_state_protect: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eir_server_owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eir_server_scope: {
                    let (v, fsz) =
                        xdr_codec::unpack_opaque_flex(input, Some(NFS4_OPAQUE_LIMIT as usize))?;
                    sz += fsz;
                    v
                },
                eir_server_impl_id: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for FREE_STATEID4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(FREE_STATEID4args, usize)> {
        let mut sz = 0;
        Ok((
            FREE_STATEID4args {
                fsa_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for FREE_STATEID4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(FREE_STATEID4res, usize)> {
        let mut sz = 0;
        Ok((
            FREE_STATEID4res {
                fsr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            GETATTR4args {
                attr_request: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GETATTR4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => GETATTR4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETATTR4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETATTR4resok, usize)> {
        let mut sz = 0;
        Ok((
            GETATTR4resok {
                obj_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETDEVICEINFO4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETDEVICEINFO4args, usize)> {
        let mut sz = 0;
        Ok((
            GETDEVICEINFO4args {
                gdia_device_id: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdia_layout_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdia_maxcount: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdia_notify_types: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETDEVICEINFO4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETDEVICEINFO4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GETDEVICEINFO4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10005i32 as i32) => GETDEVICEINFO4res::NFS4ERR_TOOSMALL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => GETDEVICEINFO4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETDEVICEINFO4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETDEVICEINFO4resok, usize)> {
        let mut sz = 0;
        Ok((
            GETDEVICEINFO4resok {
                gdir_device_addr: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdir_notification: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETDEVICELIST4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETDEVICELIST4args, usize)> {
        let mut sz = 0;
        Ok((
            GETDEVICELIST4args {
                gdla_layout_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdla_maxdevices: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdla_cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdla_cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETDEVICELIST4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETDEVICELIST4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GETDEVICELIST4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => GETDEVICELIST4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETDEVICELIST4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETDEVICELIST4resok, usize)> {
        let mut sz = 0;
        Ok((
            GETDEVICELIST4resok {
                gdlr_cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdlr_cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdlr_deviceid_list: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                gdlr_eof: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETFH4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETFH4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GETFH4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => GETFH4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETFH4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETFH4resok, usize)> {
        let mut sz = 0;
        Ok((
            GETFH4resok {
                object: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETXATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETXATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            GETXATTR4args {
                gxa_name: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GETXATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GETXATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GETXATTR4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => GETXATTR4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GET_DIR_DELEGATION4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GET_DIR_DELEGATION4args, usize)> {
        let mut sz = 0;
        Ok((
            GET_DIR_DELEGATION4args {
                gdda_signal_deleg_avail: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdda_notification_types: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdda_child_attr_delay: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdda_dir_attr_delay: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdda_child_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gdda_dir_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GET_DIR_DELEGATION4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GET_DIR_DELEGATION4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GET_DIR_DELEGATION4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => GET_DIR_DELEGATION4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GET_DIR_DELEGATION4res_non_fatal {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GET_DIR_DELEGATION4res_non_fatal, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => GET_DIR_DELEGATION4res_non_fatal::GDD4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (1i32 as i32) => GET_DIR_DELEGATION4res_non_fatal::GDD4_UNAVAIL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for GET_DIR_DELEGATION4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(GET_DIR_DELEGATION4resok, usize)> {
        let mut sz = 0;
        Ok((
            GET_DIR_DELEGATION4resok {
                gddr_cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gddr_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gddr_notification: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gddr_child_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gddr_dir_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ILLEGAL4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ILLEGAL4res, usize)> {
        let mut sz = 0;
        Ok((
            ILLEGAL4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTCOMMIT4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTCOMMIT4args, usize)> {
        let mut sz = 0;
        Ok((
            LAYOUTCOMMIT4args {
                loca_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loca_length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loca_reclaim: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loca_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loca_last_write_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loca_time_modify: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loca_layoutupdate: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTCOMMIT4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTCOMMIT4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LAYOUTCOMMIT4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LAYOUTCOMMIT4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTCOMMIT4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTCOMMIT4resok, usize)> {
        let mut sz = 0;
        Ok((
            LAYOUTCOMMIT4resok {
                locr_newsize: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTGET4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTGET4args, usize)> {
        let mut sz = 0;
        Ok((
            LAYOUTGET4args {
                loga_signal_layout_avail: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_layout_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_iomode: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_minlength: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loga_maxcount: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTGET4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTGET4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LAYOUTGET4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10058i32 as i32) => LAYOUTGET4res::NFS4ERR_LAYOUTTRYLATER({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LAYOUTGET4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTGET4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTGET4resok, usize)> {
        let mut sz = 0;
        Ok((
            LAYOUTGET4resok {
                logr_return_on_close: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                logr_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                logr_layout: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTRETURN4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTRETURN4args, usize)> {
        let mut sz = 0;
        Ok((
            LAYOUTRETURN4args {
                lora_reclaim: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lora_layout_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lora_iomode: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lora_layoutreturn: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LAYOUTRETURN4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LAYOUTRETURN4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LAYOUTRETURN4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LAYOUTRETURN4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LINK4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LINK4args, usize)> {
        let mut sz = 0;
        Ok((
            LINK4args {
                newname: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LINK4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LINK4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LINK4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LINK4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LINK4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LINK4resok, usize)> {
        let mut sz = 0;
        Ok((
            LINK4resok {
                cinfo: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LISTXATTRS4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LISTXATTRS4args, usize)> {
        let mut sz = 0;
        Ok((
            LISTXATTRS4args {
                lxa_cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lxa_maxcount: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LISTXATTRS4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LISTXATTRS4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LISTXATTRS4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LISTXATTRS4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LISTXATTRS4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LISTXATTRS4resok, usize)> {
        let mut sz = 0;
        Ok((
            LISTXATTRS4resok {
                lxr_cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lxr_names: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                lxr_eof: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCK4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCK4args, usize)> {
        let mut sz = 0;
        Ok((
            LOCK4args {
                locktype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                reclaim: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                locker: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCK4denied {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCK4denied, usize)> {
        let mut sz = 0;
        Ok((
            LOCK4denied {
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                locktype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCK4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCK4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LOCK4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10010i32 as i32) => LOCK4res::NFS4ERR_DENIED({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LOCK4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCK4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCK4resok, usize)> {
        let mut sz = 0;
        Ok((
            LOCK4resok {
                lock_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCKT4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCKT4args, usize)> {
        let mut sz = 0;
        Ok((
            LOCKT4args {
                locktype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCKT4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCKT4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (10010i32 as i32) => LOCKT4res::NFS4ERR_DENIED({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (0i32 as i32) => LOCKT4res::NFS4_OK,
                _ => LOCKT4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCKU4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCKU4args, usize)> {
        let mut sz = 0;
        Ok((
            LOCKU4args {
                locktype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lock_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOCKU4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOCKU4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => LOCKU4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => LOCKU4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOOKUP4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOOKUP4args, usize)> {
        let mut sz = 0;
        Ok((
            LOOKUP4args {
                objname: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOOKUP4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOOKUP4res, usize)> {
        let mut sz = 0;
        Ok((
            LOOKUP4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for LOOKUPP4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(LOOKUPP4res, usize)> {
        let mut sz = 0;
        Ok((
            LOOKUPP4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for NVERIFY4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(NVERIFY4args, usize)> {
        let mut sz = 0;
        Ok((
            NVERIFY4args {
                obj_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for NVERIFY4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(NVERIFY4res, usize)> {
        let mut sz = 0;
        Ok((
            NVERIFY4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN4args, usize)> {
        let mut sz = 0;
        Ok((
            OPEN4args {
                seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                share_access: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                share_deny: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                openhow: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                claim: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => OPEN4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => OPEN4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN4resok, usize)> {
        let mut sz = 0;
        Ok((
            OPEN4resok {
                stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cinfo: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                rflags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attrset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                delegation: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPENATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPENATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            OPENATTR4args {
                createdir: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPENATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPENATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            OPENATTR4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN_CONFIRM4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN_CONFIRM4args, usize)> {
        let mut sz = 0;
        Ok((
            OPEN_CONFIRM4args {
                open_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN_CONFIRM4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN_CONFIRM4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => OPEN_CONFIRM4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => OPEN_CONFIRM4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN_CONFIRM4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN_CONFIRM4resok, usize)> {
        let mut sz = 0;
        Ok((
            OPEN_CONFIRM4resok {
                open_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN_DOWNGRADE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN_DOWNGRADE4args, usize)> {
        let mut sz = 0;
        Ok((
            OPEN_DOWNGRADE4args {
                open_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                share_access: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                share_deny: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN_DOWNGRADE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN_DOWNGRADE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => OPEN_DOWNGRADE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => OPEN_DOWNGRADE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for OPEN_DOWNGRADE4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(OPEN_DOWNGRADE4resok, usize)> {
        let mut sz = 0;
        Ok((
            OPEN_DOWNGRADE4resok {
                open_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for PUTFH4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(PUTFH4args, usize)> {
        let mut sz = 0;
        Ok((
            PUTFH4args {
                object: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for PUTFH4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(PUTFH4res, usize)> {
        let mut sz = 0;
        Ok((
            PUTFH4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for PUTPUBFH4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(PUTPUBFH4res, usize)> {
        let mut sz = 0;
        Ok((
            PUTPUBFH4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for PUTROOTFH4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(PUTROOTFH4res, usize)> {
        let mut sz = 0;
        Ok((
            PUTROOTFH4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for READ4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READ4args, usize)> {
        let mut sz = 0;
        Ok((
            READ4args {
                stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                count: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for READ4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READ4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => READ4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => READ4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for READ4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READ4resok, usize)> {
        let mut sz = 0;
        let (eof, fsz) = xdr_codec::Unpack::unpack(input)?;
        sz += fsz;
        let (data_len, fsz) = xdr_codec::Unpack::unpack(input)?;
        sz += fsz;
        // Calculate the length padded to the next 4-byte boundary.
        // This is achieved by adding 3 (to ensure ceiling behavior)
        // and then clearing the lower two bits using bitwise AND with !3 (...11111100),
        // effectively rounding up to the nearest multiple of 4.
        let padded_len = (data_len + 3) & !3;

        // calculate the data payload offset from the full compound buffer
        let current_position = input.stream_position()?;
        let data_payload_offset = current_position as usize;
        // Seek to the end of the padded length
        input.seek(std::io::SeekFrom::Current(padded_len as i64))?;
        sz += padded_len;

        Ok((
            READ4resok {
                eof,
                data: DataPayload::DataRef(OpaqueRaw {
                    offset: data_payload_offset,
                    len: data_len,
                }),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for READDIR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READDIR4args, usize)> {
        let mut sz = 0;
        Ok((
            READDIR4args {
                cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                dircount: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                maxcount: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attr_request: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for READDIR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READDIR4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => READDIR4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => READDIR4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for READDIR4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READDIR4resok, usize)> {
        let mut sz = 0;
        Ok((
            READDIR4resok {
                cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                reply: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for READLINK4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READLINK4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => READLINK4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => READLINK4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for READLINK4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(READLINK4resok, usize)> {
        let mut sz = 0;
        Ok((
            READLINK4resok {
                link: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RECLAIM_COMPLETE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RECLAIM_COMPLETE4args, usize)> {
        let mut sz = 0;
        Ok((
            RECLAIM_COMPLETE4args {
                rca_one_fs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RECLAIM_COMPLETE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RECLAIM_COMPLETE4res, usize)> {
        let mut sz = 0;
        Ok((
            RECLAIM_COMPLETE4res {
                rcr_status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RELEASE_LOCKOWNER4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RELEASE_LOCKOWNER4args, usize)> {
        let mut sz = 0;
        Ok((
            RELEASE_LOCKOWNER4args {
                lock_owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RELEASE_LOCKOWNER4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RELEASE_LOCKOWNER4res, usize)> {
        let mut sz = 0;
        Ok((
            RELEASE_LOCKOWNER4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for REMOVE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(REMOVE4args, usize)> {
        let mut sz = 0;
        Ok((
            REMOVE4args {
                target: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for REMOVE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(REMOVE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => REMOVE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => REMOVE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for REMOVE4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(REMOVE4resok, usize)> {
        let mut sz = 0;
        Ok((
            REMOVE4resok {
                cinfo: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for REMOVEXATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(REMOVEXATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            REMOVEXATTR4args {
                rxa_name: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for REMOVEXATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(REMOVEXATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => REMOVEXATTR4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => REMOVEXATTR4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RENAME4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RENAME4args, usize)> {
        let mut sz = 0;
        Ok((
            RENAME4args {
                oldname: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                newname: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RENAME4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RENAME4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => RENAME4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => RENAME4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RENAME4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RENAME4resok, usize)> {
        let mut sz = 0;
        Ok((
            RENAME4resok {
                source_cinfo: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                target_cinfo: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RENEW4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RENEW4args, usize)> {
        let mut sz = 0;
        Ok((
            RENEW4args {
                clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RENEW4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RENEW4res, usize)> {
        let mut sz = 0;
        Ok((
            RENEW4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for RESTOREFH4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(RESTOREFH4res, usize)> {
        let mut sz = 0;
        Ok((
            RESTOREFH4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SAVEFH4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SAVEFH4res, usize)> {
        let mut sz = 0;
        Ok((
            SAVEFH4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SECINFO4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SECINFO4args, usize)> {
        let mut sz = 0;
        Ok((
            SECINFO4args {
                name: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SECINFO4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SECINFO4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => SECINFO4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => SECINFO4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SECINFO4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SECINFO4resok, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                SECINFO4resok(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SEQUENCE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SEQUENCE4args, usize)> {
        let mut sz = 0;
        Ok((
            SEQUENCE4args {
                sa_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sa_sequenceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sa_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sa_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sa_cachethis: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SEQUENCE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SEQUENCE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => SEQUENCE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => SEQUENCE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SEQUENCE4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SEQUENCE4resok, usize)> {
        let mut sz = 0;
        Ok((
            SEQUENCE4resok {
                sr_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sr_sequenceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sr_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sr_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sr_target_highest_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sr_status_flags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            SETATTR4args {
                stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                obj_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            SETATTR4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attrsset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETCLIENTID4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETCLIENTID4args, usize)> {
        let mut sz = 0;
        Ok((
            SETCLIENTID4args {
                client: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                callback: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                callback_ident: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETCLIENTID4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETCLIENTID4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => SETCLIENTID4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10017i32 as i32) => SETCLIENTID4res::NFS4ERR_CLID_INUSE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => SETCLIENTID4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETCLIENTID4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETCLIENTID4resok, usize)> {
        let mut sz = 0;
        Ok((
            SETCLIENTID4resok {
                clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                setclientid_confirm: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETCLIENTID_CONFIRM4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETCLIENTID_CONFIRM4args, usize)> {
        let mut sz = 0;
        Ok((
            SETCLIENTID_CONFIRM4args {
                clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                setclientid_confirm: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETCLIENTID_CONFIRM4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETCLIENTID_CONFIRM4res, usize)> {
        let mut sz = 0;
        Ok((
            SETCLIENTID_CONFIRM4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETXATTR4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETXATTR4args, usize)> {
        let mut sz = 0;
        Ok((
            SETXATTR4args {
                sxa_option: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sxa_key: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sxa_value: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SETXATTR4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SETXATTR4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => SETXATTR4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => SETXATTR4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SET_SSV4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SET_SSV4args, usize)> {
        let mut sz = 0;
        Ok((
            SET_SSV4args {
                ssa_ssv: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                ssa_digest: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SET_SSV4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SET_SSV4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => SET_SSV4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => SET_SSV4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for SET_SSV4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(SET_SSV4resok, usize)> {
        let mut sz = 0;
        Ok((
            SET_SSV4resok {
                ssr_digest: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for TEST_STATEID4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(TEST_STATEID4args, usize)> {
        let mut sz = 0;
        Ok((
            TEST_STATEID4args {
                ts_stateids: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for TEST_STATEID4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(TEST_STATEID4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => TEST_STATEID4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => TEST_STATEID4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for TEST_STATEID4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(TEST_STATEID4resok, usize)> {
        let mut sz = 0;
        Ok((
            TEST_STATEID4resok {
                tsr_status_codes: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for VERIFY4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(VERIFY4args, usize)> {
        let mut sz = 0;
        Ok((
            VERIFY4args {
                obj_attributes: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for VERIFY4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(VERIFY4res, usize)> {
        let mut sz = 0;
        Ok((
            VERIFY4res {
                status: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for WANT_DELEGATION4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(WANT_DELEGATION4args, usize)> {
        let mut sz = 0;
        Ok((
            WANT_DELEGATION4args {
                wda_want: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                wda_claim: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for WANT_DELEGATION4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(WANT_DELEGATION4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => WANT_DELEGATION4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => WANT_DELEGATION4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for WRITE4args {
    fn unpack(input: &mut In) -> xdr_codec::Result<(WRITE4args, usize)> {
        let mut sz = 0;

        let (stateid, fsz) = xdr_codec::Unpack::unpack(input)?;
        sz += fsz;
        let (offset, fsz) = xdr_codec::Unpack::unpack(input)?;
        sz += fsz;
        let (stable, fsz) = xdr_codec::Unpack::unpack(input)?;
        sz += fsz;
        let (data_len, fsz) = xdr_codec::Unpack::unpack(input)?;
        sz += fsz;

        // Calculate the length padded to the next 4-byte boundary.
        // This is achieved by adding 3 (to ensure ceiling behavior)
        // and then clearing the lower two bits using bitwise AND with !3 (...11111100),
        // effectively rounding up to the nearest multiple of 4.
        let padded_len = (data_len + 3) & !3;

        // calculate the data payload offset from the full compound buffer
        let current_position = input.stream_position()?;
        let data_payload_offset = current_position as usize;
        // Seek to the end of the padded length
        input.seek(std::io::SeekFrom::Current(padded_len as i64))?;
        sz += padded_len;

        Ok((
            WRITE4args {
                stateid,
                offset,
                stable,
                data: DataPayload::DataRef(OpaqueRaw {
                    offset: data_payload_offset,
                    len: data_len,
                }),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for WRITE4res {
    fn unpack(input: &mut In) -> xdr_codec::Result<(WRITE4res, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => WRITE4res::NFS4_OK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => WRITE4res::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for WRITE4resok {
    fn unpack(input: &mut In) -> xdr_codec::Result<(WRITE4resok, usize)> {
        let mut sz = 0;
        Ok((
            WRITE4resok {
                count: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                committed: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                writeverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for attrlist4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(attrlist4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, None)?;
                sz = usz;
                attrlist4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for auth_flavor4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(auth_flavor4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == auth_flavor4::AUTH_NONE as i32 => auth_flavor4::AUTH_NONE,
                    x if x == auth_flavor4::AUTH_SYS as i32 => auth_flavor4::AUTH_SYS,
                    x if x == auth_flavor4::RPCSEC_GSS as i32 => auth_flavor4::RPCSEC_GSS,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for authsys_parms {
    fn unpack(input: &mut In) -> xdr_codec::Result<(authsys_parms, usize)> {
        let mut sz = 0;
        Ok((
            authsys_parms {
                stamp: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                machinename: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                uid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gids: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(16i64 as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for awsfile_bypass_data_locator {
    fn unpack(input: &mut In) -> xdr_codec::Result<(awsfile_bypass_data_locator, usize)> {
        let mut sz = 0;
        Ok((
            awsfile_bypass_data_locator {
                bucket_name: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                s3_key: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                etag: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                version_id: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                count: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for bitmap4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(bitmap4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                bitmap4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for boolflag {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(boolflag, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == boolflag::FALSE as i32 => boolflag::FALSE,
                    x if x == boolflag::TRUE as i32 => boolflag::TRUE,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for callback_sec_parms4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(callback_sec_parms4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => callback_sec_parms4::AUTH_NONE,
                x if x == (1i32 as i32) => callback_sec_parms4::AUTH_SYS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (6i32 as i32) => callback_sec_parms4::RPCSEC_GSS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for cb_client4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(cb_client4, usize)> {
        let mut sz = 0;
        Ok((
            cb_client4 {
                cb_program: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cb_location: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for change_info4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(change_info4, usize)> {
        let mut sz = 0;
        Ok((
            change_info4 {
                atomic: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                before: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                after: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for change_policy4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(change_policy4, usize)> {
        let mut sz = 0;
        Ok((
            change_policy4 {
                cp_major: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cp_minor: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for channel_attrs4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(channel_attrs4, usize)> {
        let mut sz = 0;
        Ok((
            channel_attrs4 {
                ca_headerpadsize: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ca_maxrequestsize: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ca_maxresponsesize: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ca_maxresponsesize_cached: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ca_maxoperations: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ca_maxrequests: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ca_rdma_ird: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for channel_dir_from_client4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(channel_dir_from_client4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == channel_dir_from_client4::CDFC4_FORE as i32 => {
                        channel_dir_from_client4::CDFC4_FORE
                    }
                    x if x == channel_dir_from_client4::CDFC4_BACK as i32 => {
                        channel_dir_from_client4::CDFC4_BACK
                    }
                    x if x == channel_dir_from_client4::CDFC4_FORE_OR_BOTH as i32 => {
                        channel_dir_from_client4::CDFC4_FORE_OR_BOTH
                    }
                    x if x == channel_dir_from_client4::CDFC4_BACK_OR_BOTH as i32 => {
                        channel_dir_from_client4::CDFC4_BACK_OR_BOTH
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for channel_dir_from_server4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(channel_dir_from_server4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == channel_dir_from_server4::CDFS4_FORE as i32 => {
                        channel_dir_from_server4::CDFS4_FORE
                    }
                    x if x == channel_dir_from_server4::CDFS4_BACK as i32 => {
                        channel_dir_from_server4::CDFS4_BACK
                    }
                    x if x == channel_dir_from_server4::CDFS4_BOTH as i32 => {
                        channel_dir_from_server4::CDFS4_BOTH
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for client_owner4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(client_owner4, usize)> {
        let mut sz = 0;
        Ok((
            client_owner4 {
                co_verifier: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                co_ownerid: {
                    let (v, fsz) =
                        xdr_codec::unpack_opaque_flex(input, Some(NFS4_OPAQUE_LIMIT as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for createhow4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(createhow4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => createhow4::UNCHECKED4({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (1i32 as i32) => createhow4::GUARDED4({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => createhow4::EXCLUSIVE4({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (3i32 as i32) => createhow4::EXCLUSIVE4_1({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for createmode4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(createmode4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == createmode4::UNCHECKED4 as i32 => createmode4::UNCHECKED4,
                    x if x == createmode4::GUARDED4 as i32 => createmode4::GUARDED4,
                    x if x == createmode4::EXCLUSIVE4 as i32 => createmode4::EXCLUSIVE4,
                    x if x == createmode4::EXCLUSIVE4_1 as i32 => createmode4::EXCLUSIVE4_1,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for createtype4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(createtype4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (5i32 as i32) => createtype4::NF4LNK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (3i32 as i32) => createtype4::NF4BLK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (4i32 as i32) => createtype4::NF4CHR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (6i32 as i32) => createtype4::NF4SOCK,
                x if x == (7i32 as i32) => createtype4::NF4FIFO,
                x if x == (2i32 as i32) => createtype4::NF4DIR,
                _ => createtype4::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for creatverfattr {
    fn unpack(input: &mut In) -> xdr_codec::Result<(creatverfattr, usize)> {
        let mut sz = 0;
        Ok((
            creatverfattr {
                cva_verf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                cva_attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for deleg_claim4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(deleg_claim4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (4i32 as i32) => deleg_claim4::CLAIM_FH,
                x if x == (6i32 as i32) => deleg_claim4::CLAIM_DELEG_PREV_FH,
                x if x == (1i32 as i32) => deleg_claim4::CLAIM_PREVIOUS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for device_addr4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(device_addr4, usize)> {
        let mut sz = 0;
        Ok((
            device_addr4 {
                da_layout_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                da_addr_body: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for deviceid4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(deviceid4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = {
                    let mut buf: [u8; NFS4_DEVICEID4_SIZE as usize] =
                        unsafe { ::std::mem::uninitialized() };
                    let sz = xdr_codec::unpack_opaque_array(
                        input,
                        &mut buf[..],
                        NFS4_DEVICEID4_SIZE as usize,
                    )?;
                    (buf, sz)
                };
                sz = usz;
                deviceid4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for dirlist4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(dirlist4, usize)> {
        let mut sz = 0;
        Ok((
            dirlist4 {
                entries: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                eof: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for entry4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(entry4, usize)> {
        let mut sz = 0;
        Ok((
            entry4 {
                cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                name: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nextentry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for exist_lock_owner4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(exist_lock_owner4, usize)> {
        let mut sz = 0;
        Ok((
            exist_lock_owner4 {
                lock_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lock_seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fattr4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fattr4, usize)> {
        let mut sz = 0;
        Ok((
            fattr4 {
                attrmask: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                attr_vals: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fattr4_acl {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fattr4_acl, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                fattr4_acl(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fattr4_fs_layout_types {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fattr4_fs_layout_types, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                fattr4_fs_layout_types(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fattr4_layout_types {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fattr4_layout_types, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                fattr4_layout_types(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for filelayout_hint_care4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(filelayout_hint_care4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == filelayout_hint_care4::NFLH4_CARE_DENSE as i32 => {
                        filelayout_hint_care4::NFLH4_CARE_DENSE
                    }
                    x if x == filelayout_hint_care4::NFLH4_CARE_COMMIT_THRU_MDS as i32 => {
                        filelayout_hint_care4::NFLH4_CARE_COMMIT_THRU_MDS
                    }
                    x if x == filelayout_hint_care4::NFLH4_CARE_STRIPE_UNIT_SIZE as i32 => {
                        filelayout_hint_care4::NFLH4_CARE_STRIPE_UNIT_SIZE
                    }
                    x if x == filelayout_hint_care4::NFLH4_CARE_STRIPE_COUNT as i32 => {
                        filelayout_hint_care4::NFLH4_CARE_STRIPE_COUNT
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs4_status {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs4_status, usize)> {
        let mut sz = 0;
        Ok((
            fs4_status {
                fss_absent: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fss_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fss_source: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fss_current: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fss_age: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fss_version: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs4_status_type {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs4_status_type, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == fs4_status_type::STATUS4_FIXED as i32 => {
                        fs4_status_type::STATUS4_FIXED
                    }
                    x if x == fs4_status_type::STATUS4_UPDATED as i32 => {
                        fs4_status_type::STATUS4_UPDATED
                    }
                    x if x == fs4_status_type::STATUS4_VERSIONED as i32 => {
                        fs4_status_type::STATUS4_VERSIONED
                    }
                    x if x == fs4_status_type::STATUS4_WRITABLE as i32 => {
                        fs4_status_type::STATUS4_WRITABLE
                    }
                    x if x == fs4_status_type::STATUS4_REFERRAL as i32 => {
                        fs4_status_type::STATUS4_REFERRAL
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs_location4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs_location4, usize)> {
        let mut sz = 0;
        Ok((
            fs_location4 {
                server: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                rootpath: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs_locations4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs_locations4, usize)> {
        let mut sz = 0;
        Ok((
            fs_locations4 {
                fs_root: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                locations: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs_locations_info4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs_locations_info4, usize)> {
        let mut sz = 0;
        Ok((
            fs_locations_info4 {
                fli_flags: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fli_valid_for: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fli_fs_root: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fli_items: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs_locations_item4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs_locations_item4, usize)> {
        let mut sz = 0;
        Ok((
            fs_locations_item4 {
                fli_entries: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                fli_rootpath: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fs_locations_server4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fs_locations_server4, usize)> {
        let mut sz = 0;
        Ok((
            fs_locations_server4 {
                fls_currency: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                fls_info: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                fls_server: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for fsid4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(fsid4, usize)> {
        let mut sz = 0;
        Ok((
            fsid4 {
                major: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                minor: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for gddrnf4_status {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(gddrnf4_status, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == gddrnf4_status::GDD4_OK as i32 => gddrnf4_status::GDD4_OK,
                    x if x == gddrnf4_status::GDD4_UNAVAIL as i32 => gddrnf4_status::GDD4_UNAVAIL,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for gss_cb_handles4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(gss_cb_handles4, usize)> {
        let mut sz = 0;
        Ok((
            gss_cb_handles4 {
                gcbp_service: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gcbp_handle_from_server: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                gcbp_handle_from_client: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for gsshandle4_t {
    fn unpack(input: &mut In) -> xdr_codec::Result<(gsshandle4_t, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, None)?;
                sz = usz;
                gsshandle4_t(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layout4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layout4, usize)> {
        let mut sz = 0;
        Ok((
            layout4 {
                lo_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lo_length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lo_iomode: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lo_content: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layout_content4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layout_content4, usize)> {
        let mut sz = 0;
        Ok((
            layout_content4 {
                loc_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loc_body: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layouthint4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layouthint4, usize)> {
        let mut sz = 0;
        Ok((
            layouthint4 {
                loh_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                loh_body: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutiomode4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutiomode4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == layoutiomode4::LAYOUTIOMODE4_READ as i32 => {
                        layoutiomode4::LAYOUTIOMODE4_READ
                    }
                    x if x == layoutiomode4::LAYOUTIOMODE4_RW as i32 => {
                        layoutiomode4::LAYOUTIOMODE4_RW
                    }
                    x if x == layoutiomode4::LAYOUTIOMODE4_ANY as i32 => {
                        layoutiomode4::LAYOUTIOMODE4_ANY
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutrecall4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutrecall4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => layoutrecall4::LAYOUTRECALL4_FILE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => layoutrecall4::LAYOUTRECALL4_FSID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (3i32 as i32) => layoutrecall4::LAYOUTRECALL4_ALL,
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutrecall_file4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutrecall_file4, usize)> {
        let mut sz = 0;
        Ok((
            layoutrecall_file4 {
                lor_fh: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lor_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lor_length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lor_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutrecall_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutrecall_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == layoutrecall_type4::LAYOUTRECALL4_FILE as i32 => {
                        layoutrecall_type4::LAYOUTRECALL4_FILE
                    }
                    x if x == layoutrecall_type4::LAYOUTRECALL4_FSID as i32 => {
                        layoutrecall_type4::LAYOUTRECALL4_FSID
                    }
                    x if x == layoutrecall_type4::LAYOUTRECALL4_ALL as i32 => {
                        layoutrecall_type4::LAYOUTRECALL4_ALL
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutreturn4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutreturn4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => layoutreturn4::LAYOUTRETURN4_FILE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => layoutreturn4::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutreturn_file4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutreturn_file4, usize)> {
        let mut sz = 0;
        Ok((
            layoutreturn_file4 {
                lrf_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lrf_length: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lrf_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lrf_body: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutreturn_stateid {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutreturn_stateid, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => layoutreturn_stateid::TRUE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (0i32 as i32) => layoutreturn_stateid::FALSE,
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutreturn_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutreturn_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == layoutreturn_type4::LAYOUTRETURN4_FILE as i32 => {
                        layoutreturn_type4::LAYOUTRETURN4_FILE
                    }
                    x if x == layoutreturn_type4::LAYOUTRETURN4_FSID as i32 => {
                        layoutreturn_type4::LAYOUTRETURN4_FSID
                    }
                    x if x == layoutreturn_type4::LAYOUTRETURN4_ALL as i32 => {
                        layoutreturn_type4::LAYOUTRETURN4_ALL
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layouttype4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(layouttype4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == layouttype4::LAYOUT4_NFSV4_1_FILES as i32 => {
                        layouttype4::LAYOUT4_NFSV4_1_FILES
                    }
                    x if x == layouttype4::LAYOUT4_OSD2_OBJECTS as i32 => {
                        layouttype4::LAYOUT4_OSD2_OBJECTS
                    }
                    x if x == layouttype4::LAYOUT4_BLOCK_VOLUME as i32 => {
                        layouttype4::LAYOUT4_BLOCK_VOLUME
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for layoutupdate4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(layoutupdate4, usize)> {
        let mut sz = 0;
        Ok((
            layoutupdate4 {
                lou_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lou_body: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for limit_by4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(limit_by4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == limit_by4::NFS_LIMIT_SIZE as i32 => limit_by4::NFS_LIMIT_SIZE,
                    x if x == limit_by4::NFS_LIMIT_BLOCKS as i32 => limit_by4::NFS_LIMIT_BLOCKS,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for locker4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(locker4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => locker4::TRUE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (0i32 as i32) => locker4::FALSE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for mdsthreshold4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(mdsthreshold4, usize)> {
        let mut sz = 0;
        Ok((
            mdsthreshold4 {
                mth_hints: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for mode_masked4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(mode_masked4, usize)> {
        let mut sz = 0;
        Ok((
            mode_masked4 {
                mm_value_to_set: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                mm_mask_bits: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for multipath_list4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(multipath_list4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                multipath_list4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for netaddr4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(netaddr4, usize)> {
        let mut sz = 0;
        Ok((
            netaddr4 {
                na_r_netid: {
                    let (v, fsz) = xdr_codec::unpack_string(input, None)?;
                    sz += fsz;
                    v
                },
                na_r_addr: {
                    let (v, fsz) = xdr_codec::unpack_string(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for newoffset4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(newoffset4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => newoffset4::TRUE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (0i32 as i32) => newoffset4::FALSE,
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for newsize4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(newsize4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => newsize4::TRUE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (0i32 as i32) => newsize4::FALSE,
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for newtime4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(newtime4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => newtime4::TRUE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (0i32 as i32) => newtime4::FALSE,
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for nfs_argop4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_argop4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (3i32 as i32) => nfs_argop4::OP_ACCESS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (4i32 as i32) => nfs_argop4::OP_CLOSE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (5i32 as i32) => nfs_argop4::OP_COMMIT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (6i32 as i32) => nfs_argop4::OP_CREATE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (7i32 as i32) => nfs_argop4::OP_DELEGPURGE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (8i32 as i32) => nfs_argop4::OP_DELEGRETURN({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (9i32 as i32) => nfs_argop4::OP_GETATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10i32 as i32) => nfs_argop4::OP_GETFH,
                x if x == (11i32 as i32) => nfs_argop4::OP_LINK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (12i32 as i32) => nfs_argop4::OP_LOCK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (13i32 as i32) => nfs_argop4::OP_LOCKT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (14i32 as i32) => nfs_argop4::OP_LOCKU({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (15i32 as i32) => nfs_argop4::OP_LOOKUP({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (16i32 as i32) => nfs_argop4::OP_LOOKUPP,
                x if x == (17i32 as i32) => nfs_argop4::OP_NVERIFY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (18i32 as i32) => nfs_argop4::OP_OPEN({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (19i32 as i32) => nfs_argop4::OP_OPENATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (20i32 as i32) => nfs_argop4::OP_OPEN_CONFIRM({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (21i32 as i32) => nfs_argop4::OP_OPEN_DOWNGRADE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (22i32 as i32) => nfs_argop4::OP_PUTFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (23i32 as i32) => nfs_argop4::OP_PUTPUBFH,
                x if x == (24i32 as i32) => nfs_argop4::OP_PUTROOTFH,
                x if x == (25i32 as i32) => nfs_argop4::OP_READ({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (26i32 as i32) => nfs_argop4::OP_READDIR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (27i32 as i32) => nfs_argop4::OP_READLINK,
                x if x == (28i32 as i32) => nfs_argop4::OP_REMOVE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (29i32 as i32) => nfs_argop4::OP_RENAME({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (30i32 as i32) => nfs_argop4::OP_RENEW({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (31i32 as i32) => nfs_argop4::OP_RESTOREFH,
                x if x == (32i32 as i32) => nfs_argop4::OP_SAVEFH,
                x if x == (33i32 as i32) => nfs_argop4::OP_SECINFO({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (34i32 as i32) => nfs_argop4::OP_SETATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (35i32 as i32) => nfs_argop4::OP_SETCLIENTID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (36i32 as i32) => nfs_argop4::OP_SETCLIENTID_CONFIRM({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (37i32 as i32) => nfs_argop4::OP_VERIFY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (38i32 as i32) => nfs_argop4::OP_WRITE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (39i32 as i32) => nfs_argop4::OP_RELEASE_LOCKOWNER({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (40i32 as i32) => nfs_argop4::OP_BACKCHANNEL_CTL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (41i32 as i32) => nfs_argop4::OP_BIND_CONN_TO_SESSION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (42i32 as i32) => nfs_argop4::OP_EXCHANGE_ID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (43i32 as i32) => nfs_argop4::OP_CREATE_SESSION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (44i32 as i32) => nfs_argop4::OP_DESTROY_SESSION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (45i32 as i32) => nfs_argop4::OP_FREE_STATEID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (46i32 as i32) => nfs_argop4::OP_GET_DIR_DELEGATION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (47i32 as i32) => nfs_argop4::OP_GETDEVICEINFO({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (48i32 as i32) => nfs_argop4::OP_GETDEVICELIST({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (49i32 as i32) => nfs_argop4::OP_LAYOUTCOMMIT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (50i32 as i32) => nfs_argop4::OP_LAYOUTGET({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (51i32 as i32) => nfs_argop4::OP_LAYOUTRETURN({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (52i32 as i32) => nfs_argop4::OP_SECINFO_NO_NAME({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (53i32 as i32) => nfs_argop4::OP_SEQUENCE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (54i32 as i32) => nfs_argop4::OP_SET_SSV({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (55i32 as i32) => nfs_argop4::OP_TEST_STATEID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (56i32 as i32) => nfs_argop4::OP_WANT_DELEGATION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (57i32 as i32) => nfs_argop4::OP_DESTROY_CLIENTID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (58i32 as i32) => nfs_argop4::OP_RECLAIM_COMPLETE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (72i32 as i32) => nfs_argop4::OP_GETXATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (73i32 as i32) => nfs_argop4::OP_SETXATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (74i32 as i32) => nfs_argop4::OP_LISTXATTRS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (75i32 as i32) => nfs_argop4::OP_REMOVEXATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10044i32 as i32) => nfs_argop4::OP_ILLEGAL,
                x if x == (200001i32 as i32) => nfs_argop4::OP_AWSFILE_READ_BYPASS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_cb_argop4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_cb_argop4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (3i32 as i32) => nfs_cb_argop4::OP_CB_GETATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (4i32 as i32) => nfs_cb_argop4::OP_CB_RECALL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (5i32 as i32) => nfs_cb_argop4::OP_CB_LAYOUTRECALL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (6i32 as i32) => nfs_cb_argop4::OP_CB_NOTIFY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (7i32 as i32) => nfs_cb_argop4::OP_CB_PUSH_DELEG({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (8i32 as i32) => nfs_cb_argop4::OP_CB_RECALL_ANY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (9i32 as i32) => nfs_cb_argop4::OP_CB_RECALLABLE_OBJ_AVAIL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10i32 as i32) => nfs_cb_argop4::OP_CB_RECALL_SLOT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (11i32 as i32) => nfs_cb_argop4::OP_CB_SEQUENCE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (12i32 as i32) => nfs_cb_argop4::OP_CB_WANTS_CANCELLED({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (13i32 as i32) => nfs_cb_argop4::OP_CB_NOTIFY_LOCK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (14i32 as i32) => nfs_cb_argop4::OP_CB_NOTIFY_DEVICEID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10044i32 as i32) => nfs_cb_argop4::OP_CB_ILLEGAL,
                x if x == (100001i32 as i32) => nfs_cb_argop4::OP_CB_AWSFILE_HEARTBEAT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_cb_opnum4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_cb_opnum4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == nfs_cb_opnum4::OP_CB_GETATTR as i32 => nfs_cb_opnum4::OP_CB_GETATTR,
                    x if x == nfs_cb_opnum4::OP_CB_RECALL as i32 => nfs_cb_opnum4::OP_CB_RECALL,
                    x if x == nfs_cb_opnum4::OP_CB_LAYOUTRECALL as i32 => {
                        nfs_cb_opnum4::OP_CB_LAYOUTRECALL
                    }
                    x if x == nfs_cb_opnum4::OP_CB_NOTIFY as i32 => nfs_cb_opnum4::OP_CB_NOTIFY,
                    x if x == nfs_cb_opnum4::OP_CB_PUSH_DELEG as i32 => {
                        nfs_cb_opnum4::OP_CB_PUSH_DELEG
                    }
                    x if x == nfs_cb_opnum4::OP_CB_RECALL_ANY as i32 => {
                        nfs_cb_opnum4::OP_CB_RECALL_ANY
                    }
                    x if x == nfs_cb_opnum4::OP_CB_RECALLABLE_OBJ_AVAIL as i32 => {
                        nfs_cb_opnum4::OP_CB_RECALLABLE_OBJ_AVAIL
                    }
                    x if x == nfs_cb_opnum4::OP_CB_RECALL_SLOT as i32 => {
                        nfs_cb_opnum4::OP_CB_RECALL_SLOT
                    }
                    x if x == nfs_cb_opnum4::OP_CB_SEQUENCE as i32 => nfs_cb_opnum4::OP_CB_SEQUENCE,
                    x if x == nfs_cb_opnum4::OP_CB_WANTS_CANCELLED as i32 => {
                        nfs_cb_opnum4::OP_CB_WANTS_CANCELLED
                    }
                    x if x == nfs_cb_opnum4::OP_CB_NOTIFY_LOCK as i32 => {
                        nfs_cb_opnum4::OP_CB_NOTIFY_LOCK
                    }
                    x if x == nfs_cb_opnum4::OP_CB_NOTIFY_DEVICEID as i32 => {
                        nfs_cb_opnum4::OP_CB_NOTIFY_DEVICEID
                    }
                    x if x == nfs_cb_opnum4::OP_CB_ILLEGAL as i32 => nfs_cb_opnum4::OP_CB_ILLEGAL,
                    x if x == nfs_cb_opnum4::OP_CB_AWSFILE_HEARTBEAT as i32 => {
                        nfs_cb_opnum4::OP_CB_AWSFILE_HEARTBEAT
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_cb_resop4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_cb_resop4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (3i32 as i32) => nfs_cb_resop4::OP_CB_GETATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (4i32 as i32) => nfs_cb_resop4::OP_CB_RECALL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (5i32 as i32) => nfs_cb_resop4::OP_CB_LAYOUTRECALL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (6i32 as i32) => nfs_cb_resop4::OP_CB_NOTIFY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (7i32 as i32) => nfs_cb_resop4::OP_CB_PUSH_DELEG({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (8i32 as i32) => nfs_cb_resop4::OP_CB_RECALL_ANY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (9i32 as i32) => nfs_cb_resop4::OP_CB_RECALLABLE_OBJ_AVAIL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10i32 as i32) => nfs_cb_resop4::OP_CB_RECALL_SLOT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (11i32 as i32) => nfs_cb_resop4::OP_CB_SEQUENCE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (12i32 as i32) => nfs_cb_resop4::OP_CB_WANTS_CANCELLED({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (13i32 as i32) => nfs_cb_resop4::OP_CB_NOTIFY_LOCK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (14i32 as i32) => nfs_cb_resop4::OP_CB_NOTIFY_DEVICEID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10044i32 as i32) => nfs_cb_resop4::OP_CB_ILLEGAL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (100001i32 as i32) => nfs_cb_resop4::OP_CB_AWSFILE_HEARTBEAT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_client_id4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_client_id4, usize)> {
        let mut sz = 0;
        Ok((
            nfs_client_id4 {
                verifier: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                id: {
                    let (v, fsz) =
                        xdr_codec::unpack_opaque_flex(input, Some(NFS4_OPAQUE_LIMIT as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_fh4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_fh4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, Some(NFS4_FHSIZE as usize))?;
                sz = usz;
                nfs_fh4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_ftype4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_ftype4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == nfs_ftype4::NF4REG as i32 => nfs_ftype4::NF4REG,
                    x if x == nfs_ftype4::NF4DIR as i32 => nfs_ftype4::NF4DIR,
                    x if x == nfs_ftype4::NF4BLK as i32 => nfs_ftype4::NF4BLK,
                    x if x == nfs_ftype4::NF4CHR as i32 => nfs_ftype4::NF4CHR,
                    x if x == nfs_ftype4::NF4LNK as i32 => nfs_ftype4::NF4LNK,
                    x if x == nfs_ftype4::NF4SOCK as i32 => nfs_ftype4::NF4SOCK,
                    x if x == nfs_ftype4::NF4FIFO as i32 => nfs_ftype4::NF4FIFO,
                    x if x == nfs_ftype4::NF4ATTRDIR as i32 => nfs_ftype4::NF4ATTRDIR,
                    x if x == nfs_ftype4::NF4NAMEDATTR as i32 => nfs_ftype4::NF4NAMEDATTR,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_impl_id4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_impl_id4, usize)> {
        let mut sz = 0;
        Ok((
            nfs_impl_id4 {
                nii_domain: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nii_name: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nii_date: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_lock_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_lock_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == nfs_lock_type4::READ_LT as i32 => nfs_lock_type4::READ_LT,
                    x if x == nfs_lock_type4::WRITE_LT as i32 => nfs_lock_type4::WRITE_LT,
                    x if x == nfs_lock_type4::READW_LT as i32 => nfs_lock_type4::READW_LT,
                    x if x == nfs_lock_type4::WRITEW_LT as i32 => nfs_lock_type4::WRITEW_LT,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_modified_limit4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_modified_limit4, usize)> {
        let mut sz = 0;
        Ok((
            nfs_modified_limit4 {
                num_blocks: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                bytes_per_block: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_opnum4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_opnum4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == nfs_opnum4::OP_ACCESS as i32 => nfs_opnum4::OP_ACCESS,
                    x if x == nfs_opnum4::OP_CLOSE as i32 => nfs_opnum4::OP_CLOSE,
                    x if x == nfs_opnum4::OP_COMMIT as i32 => nfs_opnum4::OP_COMMIT,
                    x if x == nfs_opnum4::OP_CREATE as i32 => nfs_opnum4::OP_CREATE,
                    x if x == nfs_opnum4::OP_DELEGPURGE as i32 => nfs_opnum4::OP_DELEGPURGE,
                    x if x == nfs_opnum4::OP_DELEGRETURN as i32 => nfs_opnum4::OP_DELEGRETURN,
                    x if x == nfs_opnum4::OP_GETATTR as i32 => nfs_opnum4::OP_GETATTR,
                    x if x == nfs_opnum4::OP_GETFH as i32 => nfs_opnum4::OP_GETFH,
                    x if x == nfs_opnum4::OP_LINK as i32 => nfs_opnum4::OP_LINK,
                    x if x == nfs_opnum4::OP_LOCK as i32 => nfs_opnum4::OP_LOCK,
                    x if x == nfs_opnum4::OP_LOCKT as i32 => nfs_opnum4::OP_LOCKT,
                    x if x == nfs_opnum4::OP_LOCKU as i32 => nfs_opnum4::OP_LOCKU,
                    x if x == nfs_opnum4::OP_LOOKUP as i32 => nfs_opnum4::OP_LOOKUP,
                    x if x == nfs_opnum4::OP_LOOKUPP as i32 => nfs_opnum4::OP_LOOKUPP,
                    x if x == nfs_opnum4::OP_NVERIFY as i32 => nfs_opnum4::OP_NVERIFY,
                    x if x == nfs_opnum4::OP_OPEN as i32 => nfs_opnum4::OP_OPEN,
                    x if x == nfs_opnum4::OP_OPENATTR as i32 => nfs_opnum4::OP_OPENATTR,
                    x if x == nfs_opnum4::OP_OPEN_CONFIRM as i32 => nfs_opnum4::OP_OPEN_CONFIRM,
                    x if x == nfs_opnum4::OP_OPEN_DOWNGRADE as i32 => nfs_opnum4::OP_OPEN_DOWNGRADE,
                    x if x == nfs_opnum4::OP_PUTFH as i32 => nfs_opnum4::OP_PUTFH,
                    x if x == nfs_opnum4::OP_PUTPUBFH as i32 => nfs_opnum4::OP_PUTPUBFH,
                    x if x == nfs_opnum4::OP_PUTROOTFH as i32 => nfs_opnum4::OP_PUTROOTFH,
                    x if x == nfs_opnum4::OP_READ as i32 => nfs_opnum4::OP_READ,
                    x if x == nfs_opnum4::OP_READDIR as i32 => nfs_opnum4::OP_READDIR,
                    x if x == nfs_opnum4::OP_READLINK as i32 => nfs_opnum4::OP_READLINK,
                    x if x == nfs_opnum4::OP_REMOVE as i32 => nfs_opnum4::OP_REMOVE,
                    x if x == nfs_opnum4::OP_RENAME as i32 => nfs_opnum4::OP_RENAME,
                    x if x == nfs_opnum4::OP_RENEW as i32 => nfs_opnum4::OP_RENEW,
                    x if x == nfs_opnum4::OP_RESTOREFH as i32 => nfs_opnum4::OP_RESTOREFH,
                    x if x == nfs_opnum4::OP_SAVEFH as i32 => nfs_opnum4::OP_SAVEFH,
                    x if x == nfs_opnum4::OP_SECINFO as i32 => nfs_opnum4::OP_SECINFO,
                    x if x == nfs_opnum4::OP_SETATTR as i32 => nfs_opnum4::OP_SETATTR,
                    x if x == nfs_opnum4::OP_SETCLIENTID as i32 => nfs_opnum4::OP_SETCLIENTID,
                    x if x == nfs_opnum4::OP_SETCLIENTID_CONFIRM as i32 => {
                        nfs_opnum4::OP_SETCLIENTID_CONFIRM
                    }
                    x if x == nfs_opnum4::OP_VERIFY as i32 => nfs_opnum4::OP_VERIFY,
                    x if x == nfs_opnum4::OP_WRITE as i32 => nfs_opnum4::OP_WRITE,
                    x if x == nfs_opnum4::OP_RELEASE_LOCKOWNER as i32 => {
                        nfs_opnum4::OP_RELEASE_LOCKOWNER
                    }
                    x if x == nfs_opnum4::OP_BACKCHANNEL_CTL as i32 => {
                        nfs_opnum4::OP_BACKCHANNEL_CTL
                    }
                    x if x == nfs_opnum4::OP_BIND_CONN_TO_SESSION as i32 => {
                        nfs_opnum4::OP_BIND_CONN_TO_SESSION
                    }
                    x if x == nfs_opnum4::OP_EXCHANGE_ID as i32 => nfs_opnum4::OP_EXCHANGE_ID,
                    x if x == nfs_opnum4::OP_CREATE_SESSION as i32 => nfs_opnum4::OP_CREATE_SESSION,
                    x if x == nfs_opnum4::OP_DESTROY_SESSION as i32 => {
                        nfs_opnum4::OP_DESTROY_SESSION
                    }
                    x if x == nfs_opnum4::OP_FREE_STATEID as i32 => nfs_opnum4::OP_FREE_STATEID,
                    x if x == nfs_opnum4::OP_GET_DIR_DELEGATION as i32 => {
                        nfs_opnum4::OP_GET_DIR_DELEGATION
                    }
                    x if x == nfs_opnum4::OP_GETDEVICEINFO as i32 => nfs_opnum4::OP_GETDEVICEINFO,
                    x if x == nfs_opnum4::OP_GETDEVICELIST as i32 => nfs_opnum4::OP_GETDEVICELIST,
                    x if x == nfs_opnum4::OP_LAYOUTCOMMIT as i32 => nfs_opnum4::OP_LAYOUTCOMMIT,
                    x if x == nfs_opnum4::OP_LAYOUTGET as i32 => nfs_opnum4::OP_LAYOUTGET,
                    x if x == nfs_opnum4::OP_LAYOUTRETURN as i32 => nfs_opnum4::OP_LAYOUTRETURN,
                    x if x == nfs_opnum4::OP_SECINFO_NO_NAME as i32 => {
                        nfs_opnum4::OP_SECINFO_NO_NAME
                    }
                    x if x == nfs_opnum4::OP_SEQUENCE as i32 => nfs_opnum4::OP_SEQUENCE,
                    x if x == nfs_opnum4::OP_SET_SSV as i32 => nfs_opnum4::OP_SET_SSV,
                    x if x == nfs_opnum4::OP_TEST_STATEID as i32 => nfs_opnum4::OP_TEST_STATEID,
                    x if x == nfs_opnum4::OP_WANT_DELEGATION as i32 => {
                        nfs_opnum4::OP_WANT_DELEGATION
                    }
                    x if x == nfs_opnum4::OP_DESTROY_CLIENTID as i32 => {
                        nfs_opnum4::OP_DESTROY_CLIENTID
                    }
                    x if x == nfs_opnum4::OP_RECLAIM_COMPLETE as i32 => {
                        nfs_opnum4::OP_RECLAIM_COMPLETE
                    }
                    x if x == nfs_opnum4::OP_GETXATTR as i32 => nfs_opnum4::OP_GETXATTR,
                    x if x == nfs_opnum4::OP_SETXATTR as i32 => nfs_opnum4::OP_SETXATTR,
                    x if x == nfs_opnum4::OP_LISTXATTRS as i32 => nfs_opnum4::OP_LISTXATTRS,
                    x if x == nfs_opnum4::OP_REMOVEXATTR as i32 => nfs_opnum4::OP_REMOVEXATTR,
                    x if x == nfs_opnum4::OP_ILLEGAL as i32 => nfs_opnum4::OP_ILLEGAL,
                    x if x == nfs_opnum4::OP_AWSFILE_READ_BYPASS as i32 => {
                        nfs_opnum4::OP_AWSFILE_READ_BYPASS
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read + std::io::Seek> xdr_codec::Unpack<In> for nfs_resop4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_resop4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (3i32 as i32) => nfs_resop4::OP_ACCESS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (4i32 as i32) => nfs_resop4::OP_CLOSE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (5i32 as i32) => nfs_resop4::OP_COMMIT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (6i32 as i32) => nfs_resop4::OP_CREATE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (7i32 as i32) => nfs_resop4::OP_DELEGPURGE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (8i32 as i32) => nfs_resop4::OP_DELEGRETURN({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (9i32 as i32) => nfs_resop4::OP_GETATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10i32 as i32) => nfs_resop4::OP_GETFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (11i32 as i32) => nfs_resop4::OP_LINK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (12i32 as i32) => nfs_resop4::OP_LOCK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (13i32 as i32) => nfs_resop4::OP_LOCKT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (14i32 as i32) => nfs_resop4::OP_LOCKU({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (15i32 as i32) => nfs_resop4::OP_LOOKUP({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (16i32 as i32) => nfs_resop4::OP_LOOKUPP({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (17i32 as i32) => nfs_resop4::OP_NVERIFY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (18i32 as i32) => nfs_resop4::OP_OPEN({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (19i32 as i32) => nfs_resop4::OP_OPENATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (20i32 as i32) => nfs_resop4::OP_OPEN_CONFIRM({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (21i32 as i32) => nfs_resop4::OP_OPEN_DOWNGRADE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (22i32 as i32) => nfs_resop4::OP_PUTFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (23i32 as i32) => nfs_resop4::OP_PUTPUBFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (24i32 as i32) => nfs_resop4::OP_PUTROOTFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (25i32 as i32) => nfs_resop4::OP_READ({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (26i32 as i32) => nfs_resop4::OP_READDIR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (27i32 as i32) => nfs_resop4::OP_READLINK({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (28i32 as i32) => nfs_resop4::OP_REMOVE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (29i32 as i32) => nfs_resop4::OP_RENAME({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (30i32 as i32) => nfs_resop4::OP_RENEW({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (31i32 as i32) => nfs_resop4::OP_RESTOREFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (32i32 as i32) => nfs_resop4::OP_SAVEFH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (33i32 as i32) => nfs_resop4::OP_SECINFO({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (34i32 as i32) => nfs_resop4::OP_SETATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (35i32 as i32) => nfs_resop4::OP_SETCLIENTID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (36i32 as i32) => nfs_resop4::OP_SETCLIENTID_CONFIRM({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (37i32 as i32) => nfs_resop4::OP_VERIFY({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (38i32 as i32) => nfs_resop4::OP_WRITE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (39i32 as i32) => nfs_resop4::OP_RELEASE_LOCKOWNER({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (40i32 as i32) => nfs_resop4::OP_BACKCHANNEL_CTL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (41i32 as i32) => nfs_resop4::OP_BIND_CONN_TO_SESSION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (42i32 as i32) => nfs_resop4::OP_EXCHANGE_ID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (43i32 as i32) => nfs_resop4::OP_CREATE_SESSION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (44i32 as i32) => nfs_resop4::OP_DESTROY_SESSION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (45i32 as i32) => nfs_resop4::OP_FREE_STATEID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (46i32 as i32) => nfs_resop4::OP_GET_DIR_DELEGATION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (47i32 as i32) => nfs_resop4::OP_GETDEVICEINFO({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (48i32 as i32) => nfs_resop4::OP_GETDEVICELIST({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (49i32 as i32) => nfs_resop4::OP_LAYOUTCOMMIT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (50i32 as i32) => nfs_resop4::OP_LAYOUTGET({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (51i32 as i32) => nfs_resop4::OP_LAYOUTRETURN({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (52i32 as i32) => nfs_resop4::OP_SECINFO_NO_NAME({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (53i32 as i32) => nfs_resop4::OP_SEQUENCE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (54i32 as i32) => nfs_resop4::OP_SET_SSV({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (55i32 as i32) => nfs_resop4::OP_TEST_STATEID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (56i32 as i32) => nfs_resop4::OP_WANT_DELEGATION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (57i32 as i32) => nfs_resop4::OP_DESTROY_CLIENTID({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (58i32 as i32) => nfs_resop4::OP_RECLAIM_COMPLETE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (72i32 as i32) => nfs_resop4::OP_GETXATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (73i32 as i32) => nfs_resop4::OP_SETXATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (74i32 as i32) => nfs_resop4::OP_LISTXATTRS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (75i32 as i32) => nfs_resop4::OP_REMOVEXATTR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (10044i32 as i32) => nfs_resop4::OP_ILLEGAL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (200001i32 as i32) => nfs_resop4::OP_AWSFILE_READ_BYPASS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfs_space_limit4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfs_space_limit4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => nfs_space_limit4::NFS_LIMIT_SIZE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => nfs_space_limit4::NFS_LIMIT_BLOCKS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfsace4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfsace4, usize)> {
        let mut sz = 0;
        Ok((
            nfsace4 {
                type_: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                flag: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                access_mask: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                who: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfsacl41 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfsacl41, usize)> {
        let mut sz = 0;
        Ok((
            nfsacl41 {
                na41_flag: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                na41_aces: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfsstat4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfsstat4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == nfsstat4::NFS4_OK as i32 => nfsstat4::NFS4_OK,
                    x if x == nfsstat4::NFS4ERR_PERM as i32 => nfsstat4::NFS4ERR_PERM,
                    x if x == nfsstat4::NFS4ERR_NOENT as i32 => nfsstat4::NFS4ERR_NOENT,
                    x if x == nfsstat4::NFS4ERR_IO as i32 => nfsstat4::NFS4ERR_IO,
                    x if x == nfsstat4::NFS4ERR_NXIO as i32 => nfsstat4::NFS4ERR_NXIO,
                    x if x == nfsstat4::NFS4ERR_ACCESS as i32 => nfsstat4::NFS4ERR_ACCESS,
                    x if x == nfsstat4::NFS4ERR_EXIST as i32 => nfsstat4::NFS4ERR_EXIST,
                    x if x == nfsstat4::NFS4ERR_XDEV as i32 => nfsstat4::NFS4ERR_XDEV,
                    x if x == nfsstat4::NFS4ERR_NOTDIR as i32 => nfsstat4::NFS4ERR_NOTDIR,
                    x if x == nfsstat4::NFS4ERR_ISDIR as i32 => nfsstat4::NFS4ERR_ISDIR,
                    x if x == nfsstat4::NFS4ERR_INVAL as i32 => nfsstat4::NFS4ERR_INVAL,
                    x if x == nfsstat4::NFS4ERR_FBIG as i32 => nfsstat4::NFS4ERR_FBIG,
                    x if x == nfsstat4::NFS4ERR_NOSPC as i32 => nfsstat4::NFS4ERR_NOSPC,
                    x if x == nfsstat4::NFS4ERR_ROFS as i32 => nfsstat4::NFS4ERR_ROFS,
                    x if x == nfsstat4::NFS4ERR_MLINK as i32 => nfsstat4::NFS4ERR_MLINK,
                    x if x == nfsstat4::NFS4ERR_NAMETOOLONG as i32 => nfsstat4::NFS4ERR_NAMETOOLONG,
                    x if x == nfsstat4::NFS4ERR_NOTEMPTY as i32 => nfsstat4::NFS4ERR_NOTEMPTY,
                    x if x == nfsstat4::NFS4ERR_DQUOT as i32 => nfsstat4::NFS4ERR_DQUOT,
                    x if x == nfsstat4::NFS4ERR_STALE as i32 => nfsstat4::NFS4ERR_STALE,
                    x if x == nfsstat4::NFS4ERR_BADHANDLE as i32 => nfsstat4::NFS4ERR_BADHANDLE,
                    x if x == nfsstat4::NFS4ERR_BAD_COOKIE as i32 => nfsstat4::NFS4ERR_BAD_COOKIE,
                    x if x == nfsstat4::NFS4ERR_NOTSUPP as i32 => nfsstat4::NFS4ERR_NOTSUPP,
                    x if x == nfsstat4::NFS4ERR_TOOSMALL as i32 => nfsstat4::NFS4ERR_TOOSMALL,
                    x if x == nfsstat4::NFS4ERR_SERVERFAULT as i32 => nfsstat4::NFS4ERR_SERVERFAULT,
                    x if x == nfsstat4::NFS4ERR_BADTYPE as i32 => nfsstat4::NFS4ERR_BADTYPE,
                    x if x == nfsstat4::NFS4ERR_DELAY as i32 => nfsstat4::NFS4ERR_DELAY,
                    x if x == nfsstat4::NFS4ERR_SAME as i32 => nfsstat4::NFS4ERR_SAME,
                    x if x == nfsstat4::NFS4ERR_DENIED as i32 => nfsstat4::NFS4ERR_DENIED,
                    x if x == nfsstat4::NFS4ERR_EXPIRED as i32 => nfsstat4::NFS4ERR_EXPIRED,
                    x if x == nfsstat4::NFS4ERR_LOCKED as i32 => nfsstat4::NFS4ERR_LOCKED,
                    x if x == nfsstat4::NFS4ERR_GRACE as i32 => nfsstat4::NFS4ERR_GRACE,
                    x if x == nfsstat4::NFS4ERR_FHEXPIRED as i32 => nfsstat4::NFS4ERR_FHEXPIRED,
                    x if x == nfsstat4::NFS4ERR_SHARE_DENIED as i32 => {
                        nfsstat4::NFS4ERR_SHARE_DENIED
                    }
                    x if x == nfsstat4::NFS4ERR_WRONGSEC as i32 => nfsstat4::NFS4ERR_WRONGSEC,
                    x if x == nfsstat4::NFS4ERR_CLID_INUSE as i32 => nfsstat4::NFS4ERR_CLID_INUSE,
                    x if x == nfsstat4::NFS4ERR_RESOURCE as i32 => nfsstat4::NFS4ERR_RESOURCE,
                    x if x == nfsstat4::NFS4ERR_MOVED as i32 => nfsstat4::NFS4ERR_MOVED,
                    x if x == nfsstat4::NFS4ERR_NOFILEHANDLE as i32 => {
                        nfsstat4::NFS4ERR_NOFILEHANDLE
                    }
                    x if x == nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH as i32 => {
                        nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH
                    }
                    x if x == nfsstat4::NFS4ERR_STALE_CLIENTID as i32 => {
                        nfsstat4::NFS4ERR_STALE_CLIENTID
                    }
                    x if x == nfsstat4::NFS4ERR_STALE_STATEID as i32 => {
                        nfsstat4::NFS4ERR_STALE_STATEID
                    }
                    x if x == nfsstat4::NFS4ERR_OLD_STATEID as i32 => nfsstat4::NFS4ERR_OLD_STATEID,
                    x if x == nfsstat4::NFS4ERR_BAD_STATEID as i32 => nfsstat4::NFS4ERR_BAD_STATEID,
                    x if x == nfsstat4::NFS4ERR_BAD_SEQID as i32 => nfsstat4::NFS4ERR_BAD_SEQID,
                    x if x == nfsstat4::NFS4ERR_NOT_SAME as i32 => nfsstat4::NFS4ERR_NOT_SAME,
                    x if x == nfsstat4::NFS4ERR_LOCK_RANGE as i32 => nfsstat4::NFS4ERR_LOCK_RANGE,
                    x if x == nfsstat4::NFS4ERR_SYMLINK as i32 => nfsstat4::NFS4ERR_SYMLINK,
                    x if x == nfsstat4::NFS4ERR_RESTOREFH as i32 => nfsstat4::NFS4ERR_RESTOREFH,
                    x if x == nfsstat4::NFS4ERR_LEASE_MOVED as i32 => nfsstat4::NFS4ERR_LEASE_MOVED,
                    x if x == nfsstat4::NFS4ERR_ATTRNOTSUPP as i32 => nfsstat4::NFS4ERR_ATTRNOTSUPP,
                    x if x == nfsstat4::NFS4ERR_NO_GRACE as i32 => nfsstat4::NFS4ERR_NO_GRACE,
                    x if x == nfsstat4::NFS4ERR_RECLAIM_BAD as i32 => nfsstat4::NFS4ERR_RECLAIM_BAD,
                    x if x == nfsstat4::NFS4ERR_RECLAIM_CONFLICT as i32 => {
                        nfsstat4::NFS4ERR_RECLAIM_CONFLICT
                    }
                    x if x == nfsstat4::NFS4ERR_BADXDR as i32 => nfsstat4::NFS4ERR_BADXDR,
                    x if x == nfsstat4::NFS4ERR_LOCKS_HELD as i32 => nfsstat4::NFS4ERR_LOCKS_HELD,
                    x if x == nfsstat4::NFS4ERR_OPENMODE as i32 => nfsstat4::NFS4ERR_OPENMODE,
                    x if x == nfsstat4::NFS4ERR_BADOWNER as i32 => nfsstat4::NFS4ERR_BADOWNER,
                    x if x == nfsstat4::NFS4ERR_BADCHAR as i32 => nfsstat4::NFS4ERR_BADCHAR,
                    x if x == nfsstat4::NFS4ERR_BADNAME as i32 => nfsstat4::NFS4ERR_BADNAME,
                    x if x == nfsstat4::NFS4ERR_BAD_RANGE as i32 => nfsstat4::NFS4ERR_BAD_RANGE,
                    x if x == nfsstat4::NFS4ERR_LOCK_NOTSUPP as i32 => {
                        nfsstat4::NFS4ERR_LOCK_NOTSUPP
                    }
                    x if x == nfsstat4::NFS4ERR_OP_ILLEGAL as i32 => nfsstat4::NFS4ERR_OP_ILLEGAL,
                    x if x == nfsstat4::NFS4ERR_DEADLOCK as i32 => nfsstat4::NFS4ERR_DEADLOCK,
                    x if x == nfsstat4::NFS4ERR_FILE_OPEN as i32 => nfsstat4::NFS4ERR_FILE_OPEN,
                    x if x == nfsstat4::NFS4ERR_ADMIN_REVOKED as i32 => {
                        nfsstat4::NFS4ERR_ADMIN_REVOKED
                    }
                    x if x == nfsstat4::NFS4ERR_CB_PATH_DOWN as i32 => {
                        nfsstat4::NFS4ERR_CB_PATH_DOWN
                    }
                    x if x == nfsstat4::NFS4ERR_BADIOMODE as i32 => nfsstat4::NFS4ERR_BADIOMODE,
                    x if x == nfsstat4::NFS4ERR_BADLAYOUT as i32 => nfsstat4::NFS4ERR_BADLAYOUT,
                    x if x == nfsstat4::NFS4ERR_BAD_SESSION_DIGEST as i32 => {
                        nfsstat4::NFS4ERR_BAD_SESSION_DIGEST
                    }
                    x if x == nfsstat4::NFS4ERR_BADSESSION as i32 => nfsstat4::NFS4ERR_BADSESSION,
                    x if x == nfsstat4::NFS4ERR_BADSLOT as i32 => nfsstat4::NFS4ERR_BADSLOT,
                    x if x == nfsstat4::NFS4ERR_COMPLETE_ALREADY as i32 => {
                        nfsstat4::NFS4ERR_COMPLETE_ALREADY
                    }
                    x if x == nfsstat4::NFS4ERR_CONN_NOT_BOUND_TO_SESSION as i32 => {
                        nfsstat4::NFS4ERR_CONN_NOT_BOUND_TO_SESSION
                    }
                    x if x == nfsstat4::NFS4ERR_DELEG_ALREADY_WANTED as i32 => {
                        nfsstat4::NFS4ERR_DELEG_ALREADY_WANTED
                    }
                    x if x == nfsstat4::NFS4ERR_BACK_CHAN_BUSY as i32 => {
                        nfsstat4::NFS4ERR_BACK_CHAN_BUSY
                    }
                    x if x == nfsstat4::NFS4ERR_LAYOUTTRYLATER as i32 => {
                        nfsstat4::NFS4ERR_LAYOUTTRYLATER
                    }
                    x if x == nfsstat4::NFS4ERR_LAYOUTUNAVAILABLE as i32 => {
                        nfsstat4::NFS4ERR_LAYOUTUNAVAILABLE
                    }
                    x if x == nfsstat4::NFS4ERR_NOMATCHING_LAYOUT as i32 => {
                        nfsstat4::NFS4ERR_NOMATCHING_LAYOUT
                    }
                    x if x == nfsstat4::NFS4ERR_RECALLCONFLICT as i32 => {
                        nfsstat4::NFS4ERR_RECALLCONFLICT
                    }
                    x if x == nfsstat4::NFS4ERR_UNKNOWN_LAYOUTTYPE as i32 => {
                        nfsstat4::NFS4ERR_UNKNOWN_LAYOUTTYPE
                    }
                    x if x == nfsstat4::NFS4ERR_SEQ_MISORDERED as i32 => {
                        nfsstat4::NFS4ERR_SEQ_MISORDERED
                    }
                    x if x == nfsstat4::NFS4ERR_SEQUENCE_POS as i32 => {
                        nfsstat4::NFS4ERR_SEQUENCE_POS
                    }
                    x if x == nfsstat4::NFS4ERR_REQ_TOO_BIG as i32 => nfsstat4::NFS4ERR_REQ_TOO_BIG,
                    x if x == nfsstat4::NFS4ERR_REP_TOO_BIG as i32 => nfsstat4::NFS4ERR_REP_TOO_BIG,
                    x if x == nfsstat4::NFS4ERR_REP_TOO_BIG_TO_CACHE as i32 => {
                        nfsstat4::NFS4ERR_REP_TOO_BIG_TO_CACHE
                    }
                    x if x == nfsstat4::NFS4ERR_RETRY_UNCACHED_REP as i32 => {
                        nfsstat4::NFS4ERR_RETRY_UNCACHED_REP
                    }
                    x if x == nfsstat4::NFS4ERR_UNSAFE_COMPOUND as i32 => {
                        nfsstat4::NFS4ERR_UNSAFE_COMPOUND
                    }
                    x if x == nfsstat4::NFS4ERR_TOO_MANY_OPS as i32 => {
                        nfsstat4::NFS4ERR_TOO_MANY_OPS
                    }
                    x if x == nfsstat4::NFS4ERR_OP_NOT_IN_SESSION as i32 => {
                        nfsstat4::NFS4ERR_OP_NOT_IN_SESSION
                    }
                    x if x == nfsstat4::NFS4ERR_HASH_ALG_UNSUPP as i32 => {
                        nfsstat4::NFS4ERR_HASH_ALG_UNSUPP
                    }
                    x if x == nfsstat4::NFS4ERR_CONN_BINDING_NOT_ENFORCED as i32 => {
                        nfsstat4::NFS4ERR_CONN_BINDING_NOT_ENFORCED
                    }
                    x if x == nfsstat4::NFS4ERR_CLIENTID_BUSY as i32 => {
                        nfsstat4::NFS4ERR_CLIENTID_BUSY
                    }
                    x if x == nfsstat4::NFS4ERR_PNFS_IO_HOLE as i32 => {
                        nfsstat4::NFS4ERR_PNFS_IO_HOLE
                    }
                    x if x == nfsstat4::NFS4ERR_SEQ_FALSE_RETRY as i32 => {
                        nfsstat4::NFS4ERR_SEQ_FALSE_RETRY
                    }
                    x if x == nfsstat4::NFS4ERR_BAD_HIGH_SLOT as i32 => {
                        nfsstat4::NFS4ERR_BAD_HIGH_SLOT
                    }
                    x if x == nfsstat4::NFS4ERR_DEADSESSION as i32 => nfsstat4::NFS4ERR_DEADSESSION,
                    x if x == nfsstat4::NFS4ERR_ENCR_ALG_UNSUPP as i32 => {
                        nfsstat4::NFS4ERR_ENCR_ALG_UNSUPP
                    }
                    x if x == nfsstat4::NFS4ERR_PNFS_NO_LAYOUT as i32 => {
                        nfsstat4::NFS4ERR_PNFS_NO_LAYOUT
                    }
                    x if x == nfsstat4::NFS4ERR_NOT_ONLY_OP as i32 => nfsstat4::NFS4ERR_NOT_ONLY_OP,
                    x if x == nfsstat4::NFS4ERR_WRONG_CRED as i32 => nfsstat4::NFS4ERR_WRONG_CRED,
                    x if x == nfsstat4::NFS4ERR_WRONG_TYPE as i32 => nfsstat4::NFS4ERR_WRONG_TYPE,
                    x if x == nfsstat4::NFS4ERR_DIRDELEG_UNAVAIL as i32 => {
                        nfsstat4::NFS4ERR_DIRDELEG_UNAVAIL
                    }
                    x if x == nfsstat4::NFS4ERR_REJECT_DELEG as i32 => {
                        nfsstat4::NFS4ERR_REJECT_DELEG
                    }
                    x if x == nfsstat4::NFS4ERR_RETURNCONFLICT as i32 => {
                        nfsstat4::NFS4ERR_RETURNCONFLICT
                    }
                    x if x == nfsstat4::NFS4ERR_NOXATTR as i32 => nfsstat4::NFS4ERR_NOXATTR,
                    x if x == nfsstat4::NFS4ERR_XATTR2BIG as i32 => nfsstat4::NFS4ERR_XATTR2BIG,
                    x if x == nfsstat4::NFS4ERR_AWSFILE_BYPASS as i32 => {
                        nfsstat4::NFS4ERR_AWSFILE_BYPASS
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfstime4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfstime4, usize)> {
        let mut sz = 0;
        Ok((
            nfstime4 {
                seconds: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nseconds: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfsv4_1_file_layout4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfsv4_1_file_layout4, usize)> {
        let mut sz = 0;
        Ok((
            nfsv4_1_file_layout4 {
                nfl_deviceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nfl_util: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nfl_first_stripe_index: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nfl_pattern_offset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nfl_fh_list: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfsv4_1_file_layout_ds_addr4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfsv4_1_file_layout_ds_addr4, usize)> {
        let mut sz = 0;
        Ok((
            nfsv4_1_file_layout_ds_addr4 {
                nflda_stripe_indices: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                nflda_multipath_ds_list: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for nfsv4_1_file_layouthint4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(nfsv4_1_file_layouthint4, usize)> {
        let mut sz = 0;
        Ok((
            nfsv4_1_file_layouthint4 {
                nflh_care: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nflh_util: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nflh_stripe_count: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify4, usize)> {
        let mut sz = 0;
        Ok((
            notify4 {
                notify_mask: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                notify_vals: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_add4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_add4, usize)> {
        let mut sz = 0;
        Ok((
            notify_add4 {
                nad_old_entry: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
                nad_new_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nad_new_entry_cookie: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
                nad_prev_entry: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
                nad_last_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_attr4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_attr4, usize)> {
        let mut sz = 0;
        Ok((
            notify_attr4 {
                na_changed_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_deviceid_change4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_deviceid_change4, usize)> {
        let mut sz = 0;
        Ok((
            notify_deviceid_change4 {
                ndc_layouttype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ndc_deviceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ndc_immediate: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_deviceid_delete4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_deviceid_delete4, usize)> {
        let mut sz = 0;
        Ok((
            notify_deviceid_delete4 {
                ndd_layouttype: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ndd_deviceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_deviceid_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_deviceid_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == notify_deviceid_type4::NOTIFY_DEVICEID4_CHANGE as i32 => {
                        notify_deviceid_type4::NOTIFY_DEVICEID4_CHANGE
                    }
                    x if x == notify_deviceid_type4::NOTIFY_DEVICEID4_DELETE as i32 => {
                        notify_deviceid_type4::NOTIFY_DEVICEID4_DELETE
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_entry4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_entry4, usize)> {
        let mut sz = 0;
        Ok((
            notify_entry4 {
                ne_file: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ne_attrs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_remove4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_remove4, usize)> {
        let mut sz = 0;
        Ok((
            notify_remove4 {
                nrm_old_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nrm_old_entry_cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_rename4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_rename4, usize)> {
        let mut sz = 0;
        Ok((
            notify_rename4 {
                nrn_old_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nrn_new_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == notify_type4::NOTIFY4_CHANGE_CHILD_ATTRS as i32 => {
                        notify_type4::NOTIFY4_CHANGE_CHILD_ATTRS
                    }
                    x if x == notify_type4::NOTIFY4_CHANGE_DIR_ATTRS as i32 => {
                        notify_type4::NOTIFY4_CHANGE_DIR_ATTRS
                    }
                    x if x == notify_type4::NOTIFY4_REMOVE_ENTRY as i32 => {
                        notify_type4::NOTIFY4_REMOVE_ENTRY
                    }
                    x if x == notify_type4::NOTIFY4_ADD_ENTRY as i32 => {
                        notify_type4::NOTIFY4_ADD_ENTRY
                    }
                    x if x == notify_type4::NOTIFY4_RENAME_ENTRY as i32 => {
                        notify_type4::NOTIFY4_RENAME_ENTRY
                    }
                    x if x == notify_type4::NOTIFY4_CHANGE_COOKIE_VERIFIER as i32 => {
                        notify_type4::NOTIFY4_CHANGE_COOKIE_VERIFIER
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notify_verifier4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notify_verifier4, usize)> {
        let mut sz = 0;
        Ok((
            notify_verifier4 {
                nv_old_cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                nv_new_cookieverf: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for notifylist4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(notifylist4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, None)?;
                sz = usz;
                notifylist4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_claim4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_claim4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => open_claim4::CLAIM_NULL({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (1i32 as i32) => open_claim4::CLAIM_PREVIOUS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => open_claim4::CLAIM_DELEGATE_CUR({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (3i32 as i32) => open_claim4::CLAIM_DELEGATE_PREV({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (4i32 as i32) => open_claim4::CLAIM_FH,
                x if x == (6i32 as i32) => open_claim4::CLAIM_DELEG_PREV_FH,
                x if x == (5i32 as i32) => open_claim4::CLAIM_DELEG_CUR_FH({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_claim_delegate_cur4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_claim_delegate_cur4, usize)> {
        let mut sz = 0;
        Ok((
            open_claim_delegate_cur4 {
                delegate_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                file: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_claim_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_claim_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == open_claim_type4::CLAIM_NULL as i32 => open_claim_type4::CLAIM_NULL,
                    x if x == open_claim_type4::CLAIM_PREVIOUS as i32 => {
                        open_claim_type4::CLAIM_PREVIOUS
                    }
                    x if x == open_claim_type4::CLAIM_DELEGATE_CUR as i32 => {
                        open_claim_type4::CLAIM_DELEGATE_CUR
                    }
                    x if x == open_claim_type4::CLAIM_DELEGATE_PREV as i32 => {
                        open_claim_type4::CLAIM_DELEGATE_PREV
                    }
                    x if x == open_claim_type4::CLAIM_FH as i32 => open_claim_type4::CLAIM_FH,
                    x if x == open_claim_type4::CLAIM_DELEG_CUR_FH as i32 => {
                        open_claim_type4::CLAIM_DELEG_CUR_FH
                    }
                    x if x == open_claim_type4::CLAIM_DELEG_PREV_FH as i32 => {
                        open_claim_type4::CLAIM_DELEG_PREV_FH
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_delegation4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_delegation4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => open_delegation4::OPEN_DELEGATE_NONE,
                x if x == (1i32 as i32) => open_delegation4::OPEN_DELEGATE_READ({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => open_delegation4::OPEN_DELEGATE_WRITE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (3i32 as i32) => open_delegation4::OPEN_DELEGATE_NONE_EXT({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_delegation_type4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_delegation_type4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == open_delegation_type4::OPEN_DELEGATE_NONE as i32 => {
                        open_delegation_type4::OPEN_DELEGATE_NONE
                    }
                    x if x == open_delegation_type4::OPEN_DELEGATE_READ as i32 => {
                        open_delegation_type4::OPEN_DELEGATE_READ
                    }
                    x if x == open_delegation_type4::OPEN_DELEGATE_WRITE as i32 => {
                        open_delegation_type4::OPEN_DELEGATE_WRITE
                    }
                    x if x == open_delegation_type4::OPEN_DELEGATE_NONE_EXT as i32 => {
                        open_delegation_type4::OPEN_DELEGATE_NONE_EXT
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_none_delegation4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_none_delegation4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => open_none_delegation4::WND4_CONTENTION({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => open_none_delegation4::WND4_RESOURCE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => open_none_delegation4::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_read_delegation4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_read_delegation4, usize)> {
        let mut sz = 0;
        Ok((
            open_read_delegation4 {
                stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                recall: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                permissions: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_to_lock_owner4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_to_lock_owner4, usize)> {
        let mut sz = 0;
        Ok((
            open_to_lock_owner4 {
                open_seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                open_stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lock_seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                lock_owner: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for open_write_delegation4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(open_write_delegation4, usize)> {
        let mut sz = 0;
        Ok((
            open_write_delegation4 {
                stateid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                recall: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                space_limit: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                permissions: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for openflag4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(openflag4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => openflag4::OPEN4_CREATE({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => openflag4::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for opentype4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(opentype4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == opentype4::OPEN4_NOCREATE as i32 => opentype4::OPEN4_NOCREATE,
                    x if x == opentype4::OPEN4_CREATE as i32 => opentype4::OPEN4_CREATE,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for pathname4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(pathname4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_flex(input, None)?;
                sz = usz;
                pathname4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for prev_entry4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(prev_entry4, usize)> {
        let mut sz = 0;
        Ok((
            prev_entry4 {
                pe_prev_entry: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                pe_prev_entry_cookie: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for referring_call4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(referring_call4, usize)> {
        let mut sz = 0;
        Ok((
            referring_call4 {
                rc_sequenceid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                rc_slotid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for referring_call_list4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(referring_call_list4, usize)> {
        let mut sz = 0;
        Ok((
            referring_call_list4 {
                rcl_sessionid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                rcl_referring_calls: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for retention_get4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(retention_get4, usize)> {
        let mut sz = 0;
        Ok((
            retention_get4 {
                rg_duration: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                rg_begin_time: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for retention_set4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(retention_set4, usize)> {
        let mut sz = 0;
        Ok((
            retention_set4 {
                rs_enable: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                rs_duration: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, Some(1i64 as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for rpc_gss_svc_t {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(rpc_gss_svc_t, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == rpc_gss_svc_t::RPC_GSS_SVC_NONE as i32 => {
                        rpc_gss_svc_t::RPC_GSS_SVC_NONE
                    }
                    x if x == rpc_gss_svc_t::RPC_GSS_SVC_INTEGRITY as i32 => {
                        rpc_gss_svc_t::RPC_GSS_SVC_INTEGRITY
                    }
                    x if x == rpc_gss_svc_t::RPC_GSS_SVC_PRIVACY as i32 => {
                        rpc_gss_svc_t::RPC_GSS_SVC_PRIVACY
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for rpcsec_gss_info {
    fn unpack(input: &mut In) -> xdr_codec::Result<(rpcsec_gss_info, usize)> {
        let mut sz = 0;
        Ok((
            rpcsec_gss_info {
                oid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                qop: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                service: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for sec_oid4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(sec_oid4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, None)?;
                sz = usz;
                sec_oid4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for secinfo4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(secinfo4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (6i32 as i32) => secinfo4::RPCSEC_GSS({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => secinfo4::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for secinfo_style4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(secinfo_style4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == secinfo_style4::SECINFO_STYLE4_CURRENT_FH as i32 => {
                        secinfo_style4::SECINFO_STYLE4_CURRENT_FH
                    }
                    x if x == secinfo_style4::SECINFO_STYLE4_PARENT as i32 => {
                        secinfo_style4::SECINFO_STYLE4_PARENT
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for server_owner4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(server_owner4, usize)> {
        let mut sz = 0;
        Ok((
            server_owner4 {
                so_minor_id: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                so_major_id: {
                    let (v, fsz) =
                        xdr_codec::unpack_opaque_flex(input, Some(NFS4_OPAQUE_LIMIT as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for sessionid4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(sessionid4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = {
                    let mut buf: [u8; NFS4_SESSIONID_SIZE as usize] =
                        unsafe { ::std::mem::uninitialized() };
                    let sz = xdr_codec::unpack_opaque_array(
                        input,
                        &mut buf[..],
                        NFS4_SESSIONID_SIZE as usize,
                    )?;
                    (buf, sz)
                };
                sz = usz;
                sessionid4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for settime4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(settime4, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (1i32 as i32) => settime4::SET_TO_CLIENT_TIME4({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                _ => settime4::default,
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for setxattr_option4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(setxattr_option4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == setxattr_option4::SETXATTR4_EITHER as i32 => {
                        setxattr_option4::SETXATTR4_EITHER
                    }
                    x if x == setxattr_option4::SETXATTR4_CREATE as i32 => {
                        setxattr_option4::SETXATTR4_CREATE
                    }
                    x if x == setxattr_option4::SETXATTR4_REPLACE as i32 => {
                        setxattr_option4::SETXATTR4_REPLACE
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for specdata4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(specdata4, usize)> {
        let mut sz = 0;
        Ok((
            specdata4 {
                specdata1: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                specdata2: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssa_digest_input4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssa_digest_input4, usize)> {
        let mut sz = 0;
        Ok((
            ssa_digest_input4 {
                sdi_seqargs: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssr_digest_input4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssr_digest_input4, usize)> {
        let mut sz = 0;
        Ok((
            ssr_digest_input4 {
                sdi_seqres: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_mic_plain_tkn4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_mic_plain_tkn4, usize)> {
        let mut sz = 0;
        Ok((
            ssv_mic_plain_tkn4 {
                smpt_ssv_seq: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                smpt_orig_plain: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_mic_tkn4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_mic_tkn4, usize)> {
        let mut sz = 0;
        Ok((
            ssv_mic_tkn4 {
                smt_ssv_seq: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                smt_hmac: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_prot_info4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_prot_info4, usize)> {
        let mut sz = 0;
        Ok((
            ssv_prot_info4 {
                spi_ops: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                spi_hash_alg: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                spi_encr_alg: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                spi_ssv_len: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                spi_window: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                spi_handles: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_seal_cipher_tkn4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_seal_cipher_tkn4, usize)> {
        let mut sz = 0;
        Ok((
            ssv_seal_cipher_tkn4 {
                ssct_ssv_seq: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ssct_iv: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                ssct_encr_data: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                ssct_hmac: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_seal_plain_tkn4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_seal_plain_tkn4, usize)> {
        let mut sz = 0;
        Ok((
            ssv_seal_plain_tkn4 {
                sspt_confounder: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                sspt_ssv_seq: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                sspt_orig_plain: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
                sspt_pad: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_sp_parms4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_sp_parms4, usize)> {
        let mut sz = 0;
        Ok((
            ssv_sp_parms4 {
                ssp_ops: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ssp_hash_algs: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                ssp_encr_algs: {
                    let (v, fsz) = xdr_codec::unpack_flex(input, None)?;
                    sz += fsz;
                    v
                },
                ssp_window: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                ssp_num_gss_handles: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for ssv_subkey4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(ssv_subkey4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == ssv_subkey4::SSV4_SUBKEY_MIC_I2T as i32 => {
                        ssv_subkey4::SSV4_SUBKEY_MIC_I2T
                    }
                    x if x == ssv_subkey4::SSV4_SUBKEY_MIC_T2I as i32 => {
                        ssv_subkey4::SSV4_SUBKEY_MIC_T2I
                    }
                    x if x == ssv_subkey4::SSV4_SUBKEY_SEAL_I2T as i32 => {
                        ssv_subkey4::SSV4_SUBKEY_SEAL_I2T
                    }
                    x if x == ssv_subkey4::SSV4_SUBKEY_SEAL_T2I as i32 => {
                        ssv_subkey4::SSV4_SUBKEY_SEAL_T2I
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for stable_how4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(stable_how4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == stable_how4::UNSTABLE4 as i32 => stable_how4::UNSTABLE4,
                    x if x == stable_how4::DATA_SYNC4 as i32 => stable_how4::DATA_SYNC4,
                    x if x == stable_how4::FILE_SYNC4 as i32 => stable_how4::FILE_SYNC4,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for state_owner4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(state_owner4, usize)> {
        let mut sz = 0;
        Ok((
            state_owner4 {
                clientid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                owner: {
                    let (v, fsz) =
                        xdr_codec::unpack_opaque_flex(input, Some(NFS4_OPAQUE_LIMIT as usize))?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for state_protect4_a {
    fn unpack(input: &mut In) -> xdr_codec::Result<(state_protect4_a, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => state_protect4_a::SP4_NONE,
                x if x == (1i32 as i32) => state_protect4_a::SP4_MACH_CRED({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => state_protect4_a::SP4_SSV({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for state_protect4_r {
    fn unpack(input: &mut In) -> xdr_codec::Result<(state_protect4_r, usize)> {
        let mut sz = 0;
        Ok((
            match {
                let (v, dsz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += dsz;
                v
            } {
                x if x == (0i32 as i32) => state_protect4_r::SP4_NONE,
                x if x == (1i32 as i32) => state_protect4_r::SP4_MACH_CRED({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                x if x == (2i32 as i32) => state_protect4_r::SP4_SSV({
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                }),
                v => return Err(xdr_codec::Error::invalidcase(v as i32)),
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for state_protect_how4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(state_protect_how4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == state_protect_how4::SP4_NONE as i32 => state_protect_how4::SP4_NONE,
                    x if x == state_protect_how4::SP4_MACH_CRED as i32 => {
                        state_protect_how4::SP4_MACH_CRED
                    }
                    x if x == state_protect_how4::SP4_SSV as i32 => state_protect_how4::SP4_SSV,
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for state_protect_ops4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(state_protect_ops4, usize)> {
        let mut sz = 0;
        Ok((
            state_protect_ops4 {
                spo_must_enforce: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                spo_must_allow: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for stateid4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(stateid4, usize)> {
        let mut sz = 0;
        Ok((
            stateid4 {
                seqid: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                other: {
                    let (v, fsz) = {
                        let mut buf: [u8; 12i64 as usize] = unsafe { ::std::mem::uninitialized() };
                        let sz =
                            xdr_codec::unpack_opaque_array(input, &mut buf[..], 12i64 as usize)?;
                        (buf, sz)
                    };
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for threshold_item4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(threshold_item4, usize)> {
        let mut sz = 0;
        Ok((
            threshold_item4 {
                thi_layout_type: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                thi_hintset: {
                    let (v, fsz) = xdr_codec::Unpack::unpack(input)?;
                    sz += fsz;
                    v
                },
                thi_hintlist: {
                    let (v, fsz) = xdr_codec::unpack_opaque_flex(input, None)?;
                    sz += fsz;
                    v
                },
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for time_how4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(time_how4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == time_how4::SET_TO_SERVER_TIME4 as i32 => {
                        time_how4::SET_TO_SERVER_TIME4
                    }
                    x if x == time_how4::SET_TO_CLIENT_TIME4 as i32 => {
                        time_how4::SET_TO_CLIENT_TIME4
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for utf8string {
    fn unpack(input: &mut In) -> xdr_codec::Result<(utf8string, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, None)?;
                sz = usz;
                utf8string(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for verifier4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(verifier4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = {
                    let mut buf: [u8; NFS4_VERIFIER_SIZE as usize] =
                        unsafe { ::std::mem::uninitialized() };
                    let sz = xdr_codec::unpack_opaque_array(
                        input,
                        &mut buf[..],
                        NFS4_VERIFIER_SIZE as usize,
                    )?;
                    (buf, sz)
                };
                sz = usz;
                verifier4(v)
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for why_no_delegation4 {
    #[inline]
    fn unpack(input: &mut In) -> xdr_codec::Result<(why_no_delegation4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (e, esz): (i32, _) = xdr_codec::Unpack::unpack(input)?;
                sz += esz;
                match e {
                    x if x == why_no_delegation4::WND4_NOT_WANTED as i32 => {
                        why_no_delegation4::WND4_NOT_WANTED
                    }
                    x if x == why_no_delegation4::WND4_CONTENTION as i32 => {
                        why_no_delegation4::WND4_CONTENTION
                    }
                    x if x == why_no_delegation4::WND4_RESOURCE as i32 => {
                        why_no_delegation4::WND4_RESOURCE
                    }
                    x if x == why_no_delegation4::WND4_NOT_SUPP_FTYPE as i32 => {
                        why_no_delegation4::WND4_NOT_SUPP_FTYPE
                    }
                    x if x == why_no_delegation4::WND4_WRITE_DELEG_NOT_SUPP_FTYPE as i32 => {
                        why_no_delegation4::WND4_WRITE_DELEG_NOT_SUPP_FTYPE
                    }
                    x if x == why_no_delegation4::WND4_NOT_SUPP_UPGRADE as i32 => {
                        why_no_delegation4::WND4_NOT_SUPP_UPGRADE
                    }
                    x if x == why_no_delegation4::WND4_NOT_SUPP_DOWNGRADE as i32 => {
                        why_no_delegation4::WND4_NOT_SUPP_DOWNGRADE
                    }
                    x if x == why_no_delegation4::WND4_CANCELED as i32 => {
                        why_no_delegation4::WND4_CANCELED
                    }
                    x if x == why_no_delegation4::WND4_IS_DIR as i32 => {
                        why_no_delegation4::WND4_IS_DIR
                    }
                    e => return Err(xdr_codec::Error::invalidenum(e)),
                }
            },
            sz,
        ))
    }
}

impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for xattrvalue4 {
    fn unpack(input: &mut In) -> xdr_codec::Result<(xattrvalue4, usize)> {
        let mut sz = 0;
        Ok((
            {
                let (v, usz) = xdr_codec::unpack_opaque_flex(input, None)?;
                sz = usz;
                xattrvalue4(v)
            },
            sz,
        ))
    }
}
#[cfg(test)]
mod tests {
    use crate::nfs::nfs4_1_xdr_ext::{OPS_CODE_SIZE, READ4RES_FIXED_SIZE_BEFORE_PAYLOAD, WRITE4ARGS_FIXED_SIZE_BEFORE_PAYLOAD};

    use super::*;
    use bytes::Bytes;
    use std::any::Any;
    use std::io::{Cursor, Read, Write};
    use xdr_codec::{Pack, Unpack};

    // --- Tests for write4args ---

    #[test]
    fn test_write4args_pack() {
        // Prepare the input struct
        let original_data = Bytes::from_static(b"Test payload data.");
        // Size of stateid(4+12) + offset(8) + stable(4) + payload_opaque_size(4) = 32 bytes
        let data_payload_offset = 4 + 12 + 8 + 4 + 4;

        let args = WRITE4args {
            stateid: stateid4 {
                seqid: 123,
                other: [0xaa; 12],
            },
            offset: 1024,
            stable: stable_how4::DATA_SYNC4, // Enum value 1
            // The actual data is held here and packed by WRITE4args::pack itself
            data: DataPayload::Data(original_data.clone()),
        };

        // Pack the struct
        let mut buffer = Cursor::new(Vec::new());
        let packed_size = args.pack(&mut buffer).expect("Packing failed");

        // Define the expected packed bytes (struct fields only)
        let expected_bytes: Vec<u8> = [
            // stateid.seqid (123 = 0x7B)
            &[0x00, 0x00, 0x00, 0x7b][..],
            // stateid.other ([0xAA; 12])
            &[0xaa; 12][..],
            // offset (1024 = 0x400)
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00][..],
            // stable (DATA_SYNC4 = 1)
            &[0x00, 0x00, 0x00, 0x01][..],
            // data_opaque_len
            &[0x00, 0x00, 0x00, 0x12][..],
            // data
            original_data.as_ref(),
            // padding
            &[0x00; 2][..],
        ]
        .concat();

        assert_eq!(
            packed_size,
            expected_bytes.len(),
            "Packed size mismatch, expeced_bytes {:?}, got {:?}",
            expected_bytes,
            buffer
        );
        assert_eq!(buffer.into_inner(), expected_bytes, "Packed bytes mismatch");
    }
    #[test]
    fn test_write4args_unpack() {
        // Prepare the input bytes (representing a packed WRITE4args struct)
        let payload_len: usize = 18;
        let payload_offset: usize = 32; // Offset where payload would start
        let input_bytes: Vec<u8> = [
            // stateid.seqid (123 = 0x7B)
            &[0x00, 0x00, 0x00, 0x7b][..],
            // stateid.other ([0xAA; 12])
            &[0xaa; 12][..],
            // offset (1024 = 0x400)
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00][..],
            // stable (DATA_SYNC4 = 1)
            &[0x00, 0x00, 0x00, 0x01][..],
            // opaque_data.len (payload_len = 18)
            &[0x00, 0x00, 0x00, 0x12][..],
            // opaque_data
            &[0x00; 18][..],
            // padding
            &[0x00; 2][..],
        ]
        .concat();
        let expected_unpacked_size = input_bytes.len();
        let mut buffer = Cursor::new(input_bytes);

        // Unpack the struct
        let (unpacked, unpacked_size) = WRITE4args::unpack(&mut buffer).expect("Unpacking failed");

        // Assert results
        assert_eq!(
            unpacked_size, expected_unpacked_size,
            "Unpacked size should match input struct bytes length"
        );
        assert_eq!(unpacked.stateid.seqid, 123);
        assert_eq!(unpacked.stateid.other, [0xaa; 12]);
        assert_eq!(unpacked.offset, 1024);
        assert_eq!(unpacked.stable, stable_how4::DATA_SYNC4);

        // Check the data reference field specifically
        assert_eq!(unpacked.data, DataPayload::DataRef(OpaqueRaw {
            offset: payload_offset,
            len: payload_len,
        }));

        // Check that the buffer cursor is at the end of the struct data
        assert_eq!(
            buffer.position(),
            expected_unpacked_size as u64,
            "Cursor not positioned correctly after unpack"
        );
    }

    #[test]
    fn test_write4args_pack_error_missing_data() {
        // 1. Prepare the input struct with data_ref indicating data, but data field is None
        let args = WRITE4args {
            stateid: stateid4 {
                seqid: 123,
                other: [0xaa; 12],
            },
            offset: 1024,
            stable: stable_how4::DATA_SYNC4,
            // data_ref indicates a payload of 10 bytes exists
            data: DataPayload::DataRef(OpaqueRaw {
                offset: 32,
                len: 10,
            }), // offset doesn't matter here
            // Actual data payload is missing
        };

        // 2. Attempt to pack the struct
        let mut buffer = Cursor::new(Vec::new());
        let result = args.pack(&mut buffer);

        // 3. Assert that packing failed with an error
        assert!(
            result.is_err(),
            "Packing should fail when data is missing but data_ref indicates length > 0"
        );

        // Optional: Check for a specific error kind if applicable
        if let Err(e) = result {
            match e.kind() {
                // Match on the error's kind
                xdr_codec::ErrorKind::InvalidCase(_) => { /* Expected error */ }
                _ => panic!("Expected InvalidCase error, but got {:?}", e),
            }
        }
    }

    // --- Tests for compound4args with write4args ---
    #[test]
    fn test_compound4args_roundtrip_with_write() {
        let write_op_data = Bytes::from_static(b"Data within a compound request.");
        let write_op = nfs_argop4::OP_WRITE(WRITE4args {
            stateid: stateid4 {
                seqid: 789,
                other: [0xef; 12],
            },
            stable: stable_how4::DATA_SYNC4,
            offset: 8192,
            data: DataPayload::Data(write_op_data.clone()),
        });

        let getattr_op = nfs_argop4::OP_GETATTR(GETATTR4args {
            attr_request: bitmap4(vec![1, 2, 3]),
        });

        let putfh_op = nfs_argop4::OP_PUTFH(PUTFH4args {
            object: nfs_fh4(Bytes::from_static(b"some_file_handle").to_vec()),
        });
        let putfh_op_len = putfh_op
            .pack(&mut Cursor::new(Vec::new()))
            .expect("Packing putfh_op failed");

        let original = COMPOUND4args {
            tag: utf8string(Bytes::from_static(b"").to_vec()),
            minorversion: 1,
            argarray: vec![putfh_op, write_op.clone(), getattr_op],
        };

        let mut pack_buffer = Cursor::new(Vec::new());
        let _compound_packed_size = original
            .pack(&mut pack_buffer)
            .expect("Compound packing failed");

        // --- Unpacking Part ---
        let mut unpack_buffer = Cursor::new(pack_buffer.into_inner());
        let (unpacked, _compound_unpacked_size) =
            COMPOUND4args::unpack(&mut unpack_buffer).expect("Compound unpacking failed");

        assert_eq!(unpacked.tag.0, b"");
        assert_eq!(unpacked.minorversion, 1);

        // Find the WRITE op and check it
        let mut found_write = false;
        for op in &unpacked.argarray {
            if let nfs_argop4::OP_WRITE(unpacked_write) = op {
                found_write = true;
                assert_eq!(unpacked_write.offset, 8192);
                assert_eq!(unpacked_write.stable, stable_how4::DATA_SYNC4);
                assert_eq!(unpacked_write.stateid.seqid, 789);

                // Verify data_ref points correctly within the original packed buffer
                let data_ref = match unpacked_write.data {
                    DataPayload::DataRef(ref data) => {
                        assert!(
                            data.offset < (_compound_unpacked_size as usize),
                            "Data offset exceeds compound size"
                        ); // Basic sanity check
                        data
                    }
                    _ => panic!("Data should be DataRef"),
                };

                // Read the payload from the original buffer using the unpacked reference
                let mut payload_read_buffer = unpack_buffer.into_inner(); // Get the original bytes back
                let mut actual_payload = vec![0u8; data_ref.len as usize];
                let mut payload_cursor = Cursor::new(&payload_read_buffer[..]);
                // calculate the offset manually by adding up the packed ops fields before writes:
                let mut expected_offset_before_write_payload = 0;
                expected_offset_before_write_payload += 8; // tag = 0, minorversion = 4 bytes, argarray_len = 4 bytes
                expected_offset_before_write_payload += 4; // putfh_op code
                expected_offset_before_write_payload += putfh_op_len;
                expected_offset_before_write_payload += OPS_CODE_SIZE; // write4args op code
                expected_offset_before_write_payload += WRITE4ARGS_FIXED_SIZE_BEFORE_PAYLOAD;
                expected_offset_before_write_payload += 4; // data_opaque_len

                // Assert that we didn't extract data payload
                // Assert unpacked_write.data is DataRef
                assert!(matches!(unpacked_write.data, DataPayload::DataRef(_)));

                // Read the payload using the data_ref
                assert_eq!(
                    data_ref.offset,
                    expected_offset_before_write_payload as usize
                );
                payload_cursor.set_position(data_ref.offset as u64);
                payload_cursor
                    .read_exact(&mut actual_payload)
                    .expect("Failed to read payload using data_ref");

                assert_eq!(
                    actual_payload,
                    write_op_data.as_ref(),
                    "Payload read via data_ref mismatch"
                );

                break;
            }
        }
        assert!(
            found_write,
            "Did not find OP_WRITE in unpacked compound args"
        );
    }

    #[test]
    fn test_read4resok_pack() {
        // Prepare the input struct
        let original_data = Bytes::from_static(b"Read data payload.");
        // Size of eof(4) + payload_opaque_size(4) = 8 bytes
        let data_payload_offset = 4 + 4;

        let resok = READ4resok {
            eof: false,
            data: DataPayload::Data(original_data.clone()),
        };

        // Pack the struct
        let mut buffer = Cursor::new(Vec::new());
        let packed_size = resok.pack(&mut buffer).expect("Packing failed");

        // Define the expected packed bytes
        let expected_bytes: Vec<u8> = [
            // eof (false = 0)
            &[0x00, 0x00, 0x00, 0x00][..],
            // data_opaque_len (18 = 0x12)
            &[0x00, 0x00, 0x00, 0x12][..],
            // data
            original_data.as_ref(),
            // padding (to multiple of 4)
            &[0x00; 2][..],
        ]
        .concat();

        assert_eq!(
            packed_size,
            expected_bytes.len(),
            "Packed size mismatch, expected_bytes {:?}, got {:?}",
            expected_bytes,
            buffer.get_ref() // Use get_ref() to see the buffer contents without consuming it
        );
        assert_eq!(buffer.into_inner(), expected_bytes, "Packed bytes mismatch");
    }

    #[test]
    fn test_read4resok_unpack() {
        // Prepare the input bytes (representing a packed READ4resok struct)
        let payload_data = b"Unpack this data."; // 17 bytes
        let payload_len: usize = payload_data.len();
        let payload_offset: usize = 8; // Offset where payload starts (after eof and length)
        let input_bytes: Vec<u8> = [
            // eof (true = 1)
            &[0x00, 0x00, 0x00, 0x01][..],
            // opaque_data.len (payload_len = 17 = 0x11)
            &[0x00, 0x00, 0x00, 0x11][..],
            // opaque_data
            payload_data,
            // padding (to multiple of 4)
            &[0x00; 3][..],
        ]
        .concat();
        let expected_unpacked_size = input_bytes.len();
        let mut buffer = Cursor::new(input_bytes.clone()); // Clone input_bytes for potential debugging

        // Unpack the struct
        let (unpacked, unpacked_size) = READ4resok::unpack(&mut buffer).expect("Unpacking failed");

        // Assert results
        assert_eq!(
            unpacked_size, expected_unpacked_size,
            "Unpacked size ({}) should match input struct bytes length ({})",
            unpacked_size, expected_unpacked_size
        );
        assert_eq!(unpacked.eof, true, "EOF flag mismatch");

        // Check the data reference field specifically
        let data_ref = match unpacked.data {
            DataPayload::DataRef(data_ref) => data_ref,
            _ => panic!("Data should be DataRef"),
        };
        assert_eq!(data_ref.offset, payload_offset, "data_ref offset mismatch");
        assert_eq!(data_ref.len, payload_len, "data_ref length mismatch");

        // Check that the buffer cursor is at the end of the struct data
        assert_eq!(
            buffer.position(),
            expected_unpacked_size as u64,
            "Cursor position ({}) not at expected end ({}) after unpack",
            buffer.position(),
            expected_unpacked_size
        );
    }

    #[test]
    fn test_read4resok_pack_error_missing_data() {
        // 1. Prepare the input struct with data field as None
        // Assuming the pack implementation requires `data` to be Some, like WRITE4args
        let resok = READ4resok {
            eof: false,
            data: DataPayload::DataRef(OpaqueRaw {
                offset: 123,
                len: 321, // Len and offset doesn't matter here
            }),
        };

        // 2. Attempt to pack the struct
        let mut buffer = Cursor::new(Vec::new());
        let result = resok.pack(&mut buffer);

        // 3. Assert that packing failed with an error
        // This assumes pack() returns an error if data is None. If packing None
        // results in a zero-length opaque, this test needs adjustment.
        assert!(
            result.is_err(),
            "Packing should fail when data is None (assuming pack requires Some)"
        );

        // Optional: Check for a specific error kind if applicable
        if let Err(e) = result {
            match e.kind() {
                // Match on the error's kind, likely InvalidCase if mirroring WRITE4args
                xdr_codec::ErrorKind::InvalidCase(_) => { /* Expected error */ }
                _ => panic!("Expected InvalidCase error, but got {:?}", e),
            }
        }
    }

    #[test]
    fn test_compound4res_roundtrip_with_read() {
        let read_op_data = Bytes::from_static(b"Data read from server."); // 22 bytes
        let read_resok = READ4resok {
            eof: true,
            data: DataPayload::Data(read_op_data.clone())
        };
        let read_op = nfs_resop4::OP_READ(READ4res::NFS4_OK(read_resok));

        // Create some other dummy operations for context
        let putfh_op = nfs_resop4::OP_PUTFH(PUTFH4res {
            status: nfsstat4::NFS4_OK,
        }); // Status only
        let putfh_op_packed_len = putfh_op
            .pack(&mut Cursor::new(Vec::new()))
            .expect("Packing putfh_op failed"); // Should be 8 (op code + status)

        let getattr_resok = GETATTR4resok {
            obj_attributes: fattr4 {
                attrmask: bitmap4(vec![1, 2, 3]),
                attr_vals: attrlist4(vec![]),
            },
        }; // Empty attributes

        let getattr_op = nfs_resop4::OP_GETATTR(GETATTR4res::NFS4_OK(getattr_resok));
        let getattr_op_packed_len = getattr_op
            .pack(&mut Cursor::new(Vec::new()))
            .expect("Packing getattr_op failed"); // Should be 8 (op code + status) + fattr4 size

        let original = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(Bytes::from_static(b"response_tag").to_vec()),
            resarray: vec![putfh_op, read_op.clone(), getattr_op],
        };

        // --- Packing Part ---
        let mut pack_buffer = Cursor::new(Vec::new());
        let compound_packed_size = original
            .pack(&mut pack_buffer)
            .expect("Compound packing failed");
        let packed_bytes = pack_buffer.into_inner(); // Get the packed bytes

        // --- Unpacking Part ---
        let mut unpack_buffer = Cursor::new(packed_bytes.clone()); // Use clone for potential later inspection
        let (unpacked, compound_unpacked_size) =
            COMPOUND4res::unpack(&mut unpack_buffer).expect("Compound unpacking failed");

        // Basic checks on COMPOUND4res
        assert_eq!(unpacked.status, nfsstat4::NFS4_OK);
        assert_eq!(unpacked.tag.0, b"response_tag");
        assert_eq!(unpacked.resarray.len(), 3);
        assert_eq!(
            compound_unpacked_size, compound_packed_size,
            "Packed and unpacked sizes differ"
        );

        // Find the READ op result and check it
        let mut found_read = false;
        for op_res in &unpacked.resarray {
            if let nfs_resop4::OP_READ(read_res) = op_res {
                match read_res {
                    READ4res::NFS4_OK(unpacked_readok) => {
                        found_read = true;
                        assert_eq!(unpacked_readok.eof, true, "Unpacked READ op eof mismatch");

                        // Verify data_ref points correctly within the original packed buffer
                        let data_ref = match unpacked_readok.data {
                            DataPayload::DataRef(data_ref) => data_ref,
                            _ => panic!("Data should be DataRef"),
                        };
                        assert_eq!(data_ref.len, read_op_data.len(), "data_ref length mismatch");
                        assert!(
                            data_ref.offset < (compound_unpacked_size as usize),
                            "Data offset exceeds compound size"
                        ); // Basic sanity check

                        // Calculate the expected offset manually
                        // Size of: tag_len(4) + tag(?) + status(4) + resarray_len(4)
                        let mut expected_offset_before_read_payload =
                            4 + unpacked.tag.0.len() + 4 + 4;
                        // Add size of preceding ops in resarray
                        expected_offset_before_read_payload += putfh_op_packed_len; // PUTFH result size
                        expected_offset_before_read_payload += OPS_CODE_SIZE; // READ4res op code
                        expected_offset_before_read_payload += READ4RES_FIXED_SIZE_BEFORE_PAYLOAD;
                        expected_offset_before_read_payload += 4; // READ4resok data length field

                        assert_eq!(
                            data_ref.offset, expected_offset_before_read_payload as usize,
                            "data_ref offset mismatch"
                        );

                        // Read the payload from the original buffer using the unpacked reference
                        let mut actual_payload = vec![0u8; data_ref.len as usize];
                        let mut payload_cursor = Cursor::new(&packed_bytes[..]); // Read from the original bytes
                        payload_cursor.set_position(data_ref.offset as u64);
                        payload_cursor
                            .read_exact(&mut actual_payload)
                            .expect("Failed to read payload using data_ref");

                        assert_eq!(
                            actual_payload,
                            read_op_data.as_ref(),
                            "Payload read via data_ref mismatch"
                        );
                        break; // Found and checked the read op
                    }
                    _ => panic!("Expected READ4res::NFS4_OK, but got other status"),
                }
            }
        }
        assert!(
            found_read,
            "Did not find OP_READ result in unpacked compound response"
        );

        // Check buffer position after unpack
        assert_eq!(
            unpack_buffer.position(),
            compound_unpacked_size as u64,
            "Cursor position after unpacking COMPOUND4res is incorrect"
        );
    }


    #[test]
    fn test_encoding_and_parsing_nfs_compound_with_awsfile_read_bypass() {
        let mut basic_compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test_tag".to_vec()),
            resarray: vec![],
        };
        let read_data_payload = Bytes::from_static(b"Data within a compound request.");
        let read_bypass_args0 = AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
            eof: false,
            data: DataPayload::Data(read_data_payload.clone()),
        });
        let read_bypass_args1 =
            AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(AWSFILE_READ_BYPASS4resok {
                filehandle: nfs_fh4(vec![0xef; 16]),
                data_locator: awsfile_bypass_data_locator {
                    bucket_name: vec![0xef; 16],
                    s3_key: vec![0xef; 16],
                    etag: vec![0xef; 16],
                    version_id: vec![0xef; 16],
                    offset: 123,
                    count: 123,
                },
                file_size: 123,
            });

        basic_compound_res
            .resarray
            .push(nfs_resop4::OP_AWSFILE_READ_BYPASS(read_bypass_args0));
        basic_compound_res
            .resarray
            .push(nfs_resop4::OP_AWSFILE_READ_BYPASS(read_bypass_args1));

        let mut raw_bytes = Vec::new();
        basic_compound_res
            .pack(&mut raw_bytes)
            .expect("Failed to pack compound_args");
        let parsed_compound_res = COMPOUND4res::unpack(&mut Cursor::new(&raw_bytes[..]));
        assert!(parsed_compound_res.is_ok(), "Parsing failed");
        // len of compound res array is 4
        let (parsed_compound_res, _) = parsed_compound_res.unwrap();
        assert_eq!(parsed_compound_res.resarray.len(), 2);
        // check if the first res is read_bypass_args0
        assert!(matches!(
            &parsed_compound_res.resarray[0],
            nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(_))
        ));
        // check the READ4res contains data_ref, calculate the offset of the data_ref and check
        let compound_res_offset_before_op = 
            size_of::<nfsstat4>() // nfsstat4
            + size_of::<uint32_t>() // tag size
            + ((basic_compound_res.tag.0.len() + 3) & !3) // Tag
            + size_of::<uint32_t>(); // OP count
        let data_ref_offset = compound_res_offset_before_op 
        + size_of::<uint32_t>() // op code
        + size_of::<uint32_t>() // nfsstat4
        + size_of::<uint32_t>() // eof
        + size_of::<uint32_t>(); // opaque size
        if let nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(read_res)) = &parsed_compound_res.resarray[0] {
            let data_ref = &read_res.data;
            match data_ref {
                DataPayload::DataRef(data_ref) => {
                    assert_eq!(data_ref.offset, data_ref_offset);
                    assert_eq!(data_ref.len, read_data_payload.len());
                }
                _ => panic!("Expected DataPayload::DataRef"),
            }
        }
        // check if the second res is read_bypass_args1
        if let nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(bypass_resok)) = &parsed_compound_res.resarray[1] {
            assert_eq!(bypass_resok.filehandle.0, vec![0xef; 16]);
            assert_eq!(bypass_resok.data_locator.bucket_name, vec![0xef; 16]);
            assert_eq!(bypass_resok.data_locator.s3_key, vec![0xef; 16]);
            assert_eq!(bypass_resok.data_locator.etag, vec![0xef; 16]);
            assert_eq!(bypass_resok.data_locator.offset, 123);
            assert_eq!(bypass_resok.data_locator.count, 123);
            assert_eq!(bypass_resok.file_size, 123);
        } else {
            panic!("Expected OP_AWSFILE_READ_BYPASS with NFS4ERR_AWSFILE_BYPASS");
        }
    }
}
