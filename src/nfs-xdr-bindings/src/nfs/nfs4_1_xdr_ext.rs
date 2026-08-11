//! # Extensions for XDR-generated code for NFS protocol
//!
//! This code might need to be adjusted/fixed after regenerating NFS protocol code from .x file
//!

#![allow(unused)]

use xdr_codec::Pack;

use crate::nfs::error::NfsError;

use super::nfs4_1_xdr::*;

pub const OPS_CODE_SIZE: usize = 4;

//  += 4; // stateid.seqid
//  += 12; // stateid.other
//  += 8; // offset
//  += 4; // stable
pub const WRITE4ARGS_FIXED_SIZE_BEFORE_PAYLOAD: usize = 4 + 12 + 8 + 4;

//  += 4; // READ4res status (NFS4_OK)
//  += 4; // READ4resok eof
pub const READ4RES_FIXED_SIZE_BEFORE_PAYLOAD: usize = 4 + 4;

pub fn opnum_from_argop(op: &nfs_argop4) -> nfs_opnum4 {
    match op {
        nfs_argop4::OP_ACCESS(_) => nfs_opnum4::OP_ACCESS,
        nfs_argop4::OP_CLOSE(_) => nfs_opnum4::OP_CLOSE,
        nfs_argop4::OP_COMMIT(_) => nfs_opnum4::OP_COMMIT,
        nfs_argop4::OP_CREATE(_) => nfs_opnum4::OP_CREATE,
        nfs_argop4::OP_DELEGPURGE(_) => nfs_opnum4::OP_DELEGPURGE,
        nfs_argop4::OP_DELEGRETURN(_) => nfs_opnum4::OP_DELEGRETURN,
        nfs_argop4::OP_GETATTR(_) => nfs_opnum4::OP_GETATTR,
        nfs_argop4::OP_GETFH => nfs_opnum4::OP_GETFH,
        nfs_argop4::OP_LINK(_) => nfs_opnum4::OP_LINK,
        nfs_argop4::OP_LOCK(_) => nfs_opnum4::OP_LOCK,
        nfs_argop4::OP_LOCKT(_) => nfs_opnum4::OP_LOCKT,
        nfs_argop4::OP_LOCKU(_) => nfs_opnum4::OP_LOCKU,
        nfs_argop4::OP_LOOKUP(_) => nfs_opnum4::OP_LOOKUP,
        nfs_argop4::OP_LOOKUPP => nfs_opnum4::OP_LOOKUPP,
        nfs_argop4::OP_NVERIFY(_) => nfs_opnum4::OP_NVERIFY,
        nfs_argop4::OP_OPEN(_) => nfs_opnum4::OP_OPEN,
        nfs_argop4::OP_OPENATTR(_) => nfs_opnum4::OP_OPENATTR,
        nfs_argop4::OP_OPEN_CONFIRM(_) => nfs_opnum4::OP_OPEN_CONFIRM,
        nfs_argop4::OP_OPEN_DOWNGRADE(_) => nfs_opnum4::OP_OPEN_DOWNGRADE,
        nfs_argop4::OP_PUTFH(_) => nfs_opnum4::OP_PUTFH,
        nfs_argop4::OP_PUTPUBFH => nfs_opnum4::OP_PUTPUBFH,
        nfs_argop4::OP_PUTROOTFH => nfs_opnum4::OP_PUTROOTFH,
        nfs_argop4::OP_READ(_) => nfs_opnum4::OP_READ,
        nfs_argop4::OP_READDIR(_) => nfs_opnum4::OP_READDIR,
        nfs_argop4::OP_READLINK => nfs_opnum4::OP_READLINK,
        nfs_argop4::OP_REMOVE(_) => nfs_opnum4::OP_REMOVE,
        nfs_argop4::OP_RENAME(_) => nfs_opnum4::OP_RENAME,
        nfs_argop4::OP_RENEW(_) => nfs_opnum4::OP_RENEW,
        nfs_argop4::OP_RESTOREFH => nfs_opnum4::OP_RESTOREFH,
        nfs_argop4::OP_SAVEFH => nfs_opnum4::OP_SAVEFH,
        nfs_argop4::OP_SECINFO(_) => nfs_opnum4::OP_SECINFO,
        nfs_argop4::OP_SETATTR(_) => nfs_opnum4::OP_SETATTR,
        nfs_argop4::OP_SETCLIENTID(_) => nfs_opnum4::OP_SETCLIENTID,
        nfs_argop4::OP_SETCLIENTID_CONFIRM(_) => nfs_opnum4::OP_SETCLIENTID_CONFIRM,
        nfs_argop4::OP_VERIFY(_) => nfs_opnum4::OP_VERIFY,
        nfs_argop4::OP_WRITE(_) => nfs_opnum4::OP_WRITE,
        nfs_argop4::OP_RELEASE_LOCKOWNER(_) => nfs_opnum4::OP_RELEASE_LOCKOWNER,
        nfs_argop4::OP_BIND_CONN_TO_SESSION(_) => nfs_opnum4::OP_BIND_CONN_TO_SESSION,
        nfs_argop4::OP_EXCHANGE_ID(_) => nfs_opnum4::OP_EXCHANGE_ID,
        nfs_argop4::OP_CREATE_SESSION(_) => nfs_opnum4::OP_CREATE_SESSION,
        nfs_argop4::OP_DESTROY_SESSION(_) => nfs_opnum4::OP_DESTROY_SESSION,
        nfs_argop4::OP_FREE_STATEID(_) => nfs_opnum4::OP_FREE_STATEID,
        nfs_argop4::OP_GET_DIR_DELEGATION(_) => nfs_opnum4::OP_GET_DIR_DELEGATION,
        nfs_argop4::OP_GETDEVICEINFO(_) => nfs_opnum4::OP_GETDEVICEINFO,
        nfs_argop4::OP_GETDEVICELIST(_) => nfs_opnum4::OP_GETDEVICELIST,
        nfs_argop4::OP_LAYOUTCOMMIT(_) => nfs_opnum4::OP_LAYOUTCOMMIT,
        nfs_argop4::OP_LAYOUTGET(_) => nfs_opnum4::OP_LAYOUTGET,
        nfs_argop4::OP_LAYOUTRETURN(_) => nfs_opnum4::OP_LAYOUTRETURN,
        nfs_argop4::OP_SECINFO_NO_NAME(_) => nfs_opnum4::OP_SECINFO_NO_NAME,
        nfs_argop4::OP_SEQUENCE(_) => nfs_opnum4::OP_SEQUENCE,
        nfs_argop4::OP_SET_SSV(_) => nfs_opnum4::OP_SET_SSV,
        nfs_argop4::OP_TEST_STATEID(_) => nfs_opnum4::OP_TEST_STATEID,
        nfs_argop4::OP_WANT_DELEGATION(_) => nfs_opnum4::OP_WANT_DELEGATION,
        nfs_argop4::OP_DESTROY_CLIENTID(_) => nfs_opnum4::OP_DESTROY_CLIENTID,
        nfs_argop4::OP_RECLAIM_COMPLETE(_) => nfs_opnum4::OP_RECLAIM_COMPLETE,
        nfs_argop4::OP_BACKCHANNEL_CTL(_) => nfs_opnum4::OP_BACKCHANNEL_CTL,
        nfs_argop4::OP_GETXATTR(_) => nfs_opnum4::OP_GETXATTR,
        nfs_argop4::OP_SETXATTR(_) => nfs_opnum4::OP_SETXATTR,
        nfs_argop4::OP_LISTXATTRS(_) => nfs_opnum4::OP_LISTXATTRS,
        nfs_argop4::OP_REMOVEXATTR(_) => nfs_opnum4::OP_REMOVEXATTR,
        nfs_argop4::OP_AWSFILE_READ_BYPASS(_) => nfs_opnum4::OP_AWSFILE_READ_BYPASS,
        _ => nfs_opnum4::OP_ILLEGAL,
    }
}

pub fn opnum_from_resop(op: &nfs_resop4) -> nfs_opnum4 {
    match op {
        nfs_resop4::OP_ACCESS(_) => nfs_opnum4::OP_ACCESS,
        nfs_resop4::OP_CLOSE(_) => nfs_opnum4::OP_CLOSE,
        nfs_resop4::OP_COMMIT(_) => nfs_opnum4::OP_COMMIT,
        nfs_resop4::OP_CREATE(_) => nfs_opnum4::OP_CREATE,
        nfs_resop4::OP_DELEGPURGE(_) => nfs_opnum4::OP_DELEGPURGE,
        nfs_resop4::OP_DELEGRETURN(_) => nfs_opnum4::OP_DELEGRETURN,
        nfs_resop4::OP_GETATTR(_) => nfs_opnum4::OP_GETATTR,
        nfs_resop4::OP_GETFH(_) => nfs_opnum4::OP_GETFH,
        nfs_resop4::OP_LINK(_) => nfs_opnum4::OP_LINK,
        nfs_resop4::OP_LOCK(_) => nfs_opnum4::OP_LOCK,
        nfs_resop4::OP_LOCKT(_) => nfs_opnum4::OP_LOCKT,
        nfs_resop4::OP_LOCKU(_) => nfs_opnum4::OP_LOCKU,
        nfs_resop4::OP_LOOKUP(_) => nfs_opnum4::OP_LOOKUP,
        nfs_resop4::OP_LOOKUPP(_) => nfs_opnum4::OP_LOOKUPP,
        nfs_resop4::OP_NVERIFY(_) => nfs_opnum4::OP_NVERIFY,
        nfs_resop4::OP_OPEN(_) => nfs_opnum4::OP_OPEN,
        nfs_resop4::OP_OPENATTR(_) => nfs_opnum4::OP_OPENATTR,
        nfs_resop4::OP_OPEN_CONFIRM(_) => nfs_opnum4::OP_OPEN_CONFIRM,
        nfs_resop4::OP_OPEN_DOWNGRADE(_) => nfs_opnum4::OP_OPEN_DOWNGRADE,
        nfs_resop4::OP_PUTFH(_) => nfs_opnum4::OP_PUTFH,
        nfs_resop4::OP_PUTPUBFH(_) => nfs_opnum4::OP_PUTPUBFH,
        nfs_resop4::OP_PUTROOTFH(_) => nfs_opnum4::OP_PUTROOTFH,
        nfs_resop4::OP_READ(_) => nfs_opnum4::OP_READ,
        nfs_resop4::OP_READDIR(_) => nfs_opnum4::OP_READDIR,
        nfs_resop4::OP_READLINK(_) => nfs_opnum4::OP_READLINK,
        nfs_resop4::OP_REMOVE(_) => nfs_opnum4::OP_REMOVE,
        nfs_resop4::OP_RENAME(_) => nfs_opnum4::OP_RENAME,
        nfs_resop4::OP_RENEW(_) => nfs_opnum4::OP_RENEW,
        nfs_resop4::OP_RESTOREFH(_) => nfs_opnum4::OP_RESTOREFH,
        nfs_resop4::OP_SAVEFH(_) => nfs_opnum4::OP_SAVEFH,
        nfs_resop4::OP_SECINFO(_) => nfs_opnum4::OP_SECINFO,
        nfs_resop4::OP_SETATTR(_) => nfs_opnum4::OP_SETATTR,
        nfs_resop4::OP_SETCLIENTID(_) => nfs_opnum4::OP_SETCLIENTID,
        nfs_resop4::OP_SETCLIENTID_CONFIRM(_) => nfs_opnum4::OP_SETCLIENTID_CONFIRM,
        nfs_resop4::OP_VERIFY(_) => nfs_opnum4::OP_VERIFY,
        nfs_resop4::OP_WRITE(_) => nfs_opnum4::OP_WRITE,
        nfs_resop4::OP_RELEASE_LOCKOWNER(_) => nfs_opnum4::OP_RELEASE_LOCKOWNER,
        nfs_resop4::OP_BIND_CONN_TO_SESSION(_) => nfs_opnum4::OP_BIND_CONN_TO_SESSION,
        nfs_resop4::OP_EXCHANGE_ID(_) => nfs_opnum4::OP_EXCHANGE_ID,
        nfs_resop4::OP_CREATE_SESSION(_) => nfs_opnum4::OP_CREATE_SESSION,
        nfs_resop4::OP_DESTROY_SESSION(_) => nfs_opnum4::OP_DESTROY_SESSION,
        nfs_resop4::OP_FREE_STATEID(_) => nfs_opnum4::OP_FREE_STATEID,
        nfs_resop4::OP_GET_DIR_DELEGATION(_) => nfs_opnum4::OP_GET_DIR_DELEGATION,
        nfs_resop4::OP_GETDEVICEINFO(_) => nfs_opnum4::OP_GETDEVICEINFO,
        nfs_resop4::OP_GETDEVICELIST(_) => nfs_opnum4::OP_GETDEVICELIST,
        nfs_resop4::OP_LAYOUTCOMMIT(_) => nfs_opnum4::OP_LAYOUTCOMMIT,
        nfs_resop4::OP_LAYOUTGET(_) => nfs_opnum4::OP_LAYOUTGET,
        nfs_resop4::OP_LAYOUTRETURN(_) => nfs_opnum4::OP_LAYOUTRETURN,
        nfs_resop4::OP_SECINFO_NO_NAME(_) => nfs_opnum4::OP_SECINFO_NO_NAME,
        nfs_resop4::OP_SEQUENCE(_) => nfs_opnum4::OP_SEQUENCE,
        nfs_resop4::OP_SET_SSV(_) => nfs_opnum4::OP_SET_SSV,
        nfs_resop4::OP_TEST_STATEID(_) => nfs_opnum4::OP_TEST_STATEID,
        nfs_resop4::OP_WANT_DELEGATION(_) => nfs_opnum4::OP_WANT_DELEGATION,
        nfs_resop4::OP_DESTROY_CLIENTID(_) => nfs_opnum4::OP_DESTROY_CLIENTID,
        nfs_resop4::OP_RECLAIM_COMPLETE(_) => nfs_opnum4::OP_RECLAIM_COMPLETE,
        nfs_resop4::OP_BACKCHANNEL_CTL(_) => nfs_opnum4::OP_BACKCHANNEL_CTL,
        nfs_resop4::OP_GETXATTR(_) => nfs_opnum4::OP_GETXATTR,
        nfs_resop4::OP_SETXATTR(_) => nfs_opnum4::OP_SETXATTR,
        nfs_resop4::OP_LISTXATTRS(_) => nfs_opnum4::OP_LISTXATTRS,
        nfs_resop4::OP_REMOVEXATTR(_) => nfs_opnum4::OP_REMOVEXATTR,
        nfs_resop4::OP_AWSFILE_READ_BYPASS(_) => nfs_opnum4::OP_AWSFILE_READ_BYPASS,
        _ => nfs_opnum4::OP_ILLEGAL,
    }
}

impl nfs_cb_resop4 {
    pub fn get_status(&self) -> nfsstat4 {
        match self {
            nfs_cb_resop4::OP_CB_GETATTR(_) => {
                if matches!(
                    self,
                    nfs_cb_resop4::OP_CB_GETATTR(CB_GETATTR4res::NFS4_OK(_))
                ) {
                    nfsstat4::NFS4_OK
                } else {
                    nfsstat4::NFS4ERR_SERVERFAULT
                }
            }
            nfs_cb_resop4::OP_CB_RECALL(res) => res.status,
            nfs_cb_resop4::OP_CB_LAYOUTRECALL(res) => res.clorr_status,
            nfs_cb_resop4::OP_CB_NOTIFY(res) => res.cnr_status,
            nfs_cb_resop4::OP_CB_PUSH_DELEG(res) => res.cpdr_status,
            nfs_cb_resop4::OP_CB_RECALL_ANY(res) => res.crar_status,
            nfs_cb_resop4::OP_CB_RECALLABLE_OBJ_AVAIL(res) => res.croa_status,
            nfs_cb_resop4::OP_CB_RECALL_SLOT(res) => res.rsr_status,
            nfs_cb_resop4::OP_CB_SEQUENCE(_) => {
                if matches!(
                    self,
                    nfs_cb_resop4::OP_CB_SEQUENCE(CB_SEQUENCE4res::NFS4_OK(_))
                ) {
                    nfsstat4::NFS4_OK
                } else {
                    nfsstat4::NFS4ERR_SERVERFAULT
                }
            }
            nfs_cb_resop4::OP_CB_WANTS_CANCELLED(res) => res.cwcr_status,
            nfs_cb_resop4::OP_CB_NOTIFY_LOCK(res) => res.cnlr_status,
            nfs_cb_resop4::OP_CB_NOTIFY_DEVICEID(res) => res.cndr_status,
            nfs_cb_resop4::OP_CB_ILLEGAL(res) => res.status,
            nfs_cb_resop4::OP_CB_AWSFILE_HEARTBEAT(res) => res.hb_status,
        }
    }
}

pub fn opnum_from_cb_argop(argop: &nfs_cb_argop4) -> nfs_cb_opnum4 {
    match argop {
        nfs_cb_argop4::OP_CB_GETATTR(_) => nfs_cb_opnum4::OP_CB_GETATTR,
        nfs_cb_argop4::OP_CB_RECALL(_) => nfs_cb_opnum4::OP_CB_RECALL,
        nfs_cb_argop4::OP_CB_LAYOUTRECALL(_) => nfs_cb_opnum4::OP_CB_LAYOUTRECALL,
        nfs_cb_argop4::OP_CB_NOTIFY(_) => nfs_cb_opnum4::OP_CB_NOTIFY,
        nfs_cb_argop4::OP_CB_PUSH_DELEG(_) => nfs_cb_opnum4::OP_CB_PUSH_DELEG,
        nfs_cb_argop4::OP_CB_RECALL_ANY(_) => nfs_cb_opnum4::OP_CB_RECALL_ANY,
        nfs_cb_argop4::OP_CB_RECALLABLE_OBJ_AVAIL(_) => nfs_cb_opnum4::OP_CB_RECALLABLE_OBJ_AVAIL,
        nfs_cb_argop4::OP_CB_RECALL_SLOT(_) => nfs_cb_opnum4::OP_CB_RECALL_SLOT,
        nfs_cb_argop4::OP_CB_SEQUENCE(_) => nfs_cb_opnum4::OP_CB_SEQUENCE,
        nfs_cb_argop4::OP_CB_WANTS_CANCELLED(_) => nfs_cb_opnum4::OP_CB_WANTS_CANCELLED,
        nfs_cb_argop4::OP_CB_NOTIFY_LOCK(_) => nfs_cb_opnum4::OP_CB_NOTIFY_LOCK,
        nfs_cb_argop4::OP_CB_NOTIFY_DEVICEID(_) => nfs_cb_opnum4::OP_CB_NOTIFY_DEVICEID,
        nfs_cb_argop4::OP_CB_ILLEGAL => nfs_cb_opnum4::OP_CB_ILLEGAL,
        nfs_cb_argop4::OP_CB_AWSFILE_HEARTBEAT(_) => nfs_cb_opnum4::OP_CB_AWSFILE_HEARTBEAT,
    }
}

pub fn opnum_from_cb_resop(resop: &nfs_cb_resop4) -> nfs_cb_opnum4 {
    match resop {
        nfs_cb_resop4::OP_CB_GETATTR(_) => nfs_cb_opnum4::OP_CB_GETATTR,
        nfs_cb_resop4::OP_CB_RECALL(_) => nfs_cb_opnum4::OP_CB_RECALL,
        nfs_cb_resop4::OP_CB_LAYOUTRECALL(_) => nfs_cb_opnum4::OP_CB_LAYOUTRECALL,
        nfs_cb_resop4::OP_CB_NOTIFY(_) => nfs_cb_opnum4::OP_CB_NOTIFY,
        nfs_cb_resop4::OP_CB_PUSH_DELEG(_) => nfs_cb_opnum4::OP_CB_PUSH_DELEG,
        nfs_cb_resop4::OP_CB_RECALL_ANY(_) => nfs_cb_opnum4::OP_CB_RECALL_ANY,
        nfs_cb_resop4::OP_CB_RECALLABLE_OBJ_AVAIL(_) => nfs_cb_opnum4::OP_CB_RECALLABLE_OBJ_AVAIL,
        nfs_cb_resop4::OP_CB_RECALL_SLOT(_) => nfs_cb_opnum4::OP_CB_RECALL_SLOT,
        nfs_cb_resop4::OP_CB_SEQUENCE(_) => nfs_cb_opnum4::OP_CB_SEQUENCE,
        nfs_cb_resop4::OP_CB_WANTS_CANCELLED(_) => nfs_cb_opnum4::OP_CB_WANTS_CANCELLED,
        nfs_cb_resop4::OP_CB_NOTIFY_LOCK(_) => nfs_cb_opnum4::OP_CB_NOTIFY_LOCK,
        nfs_cb_resop4::OP_CB_NOTIFY_DEVICEID(_) => nfs_cb_opnum4::OP_CB_NOTIFY_DEVICEID,
        nfs_cb_resop4::OP_CB_ILLEGAL(_) => nfs_cb_opnum4::OP_CB_ILLEGAL,
        nfs_cb_resop4::OP_CB_AWSFILE_HEARTBEAT(_) => nfs_cb_opnum4::OP_CB_AWSFILE_HEARTBEAT,
    }
}

impl TryFrom<AWSFILE_READ_BYPASS4res> for READ4res {
    type Error = NfsError;

    fn try_from(value: AWSFILE_READ_BYPASS4res) -> Result<Self, Self::Error> {
        match value {
            AWSFILE_READ_BYPASS4res::NFS4_OK(res) => Ok(READ4res::NFS4_OK(READ4resok {
                eof: res.eof,
                data: res.data,
            })),
            AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(_) => {
                Err(NfsError::InvalidOperationReplacement)
            }
            _ => Err(NfsError::InvalidOperationReplacement),
        }
    }
}

#[inline]
pub fn get_padded_size(len: usize) -> usize {
    (len + 3) & !3
}

pub trait GetOpSerializedSize {
    fn get_op_serialized_size(op: &Self, buf: &mut Vec<u8>) -> Result<usize, NfsError>;
}

impl GetOpSerializedSize for nfs_argop4 {
    fn get_op_serialized_size(op: &nfs_argop4, buf: &mut Vec<u8>) -> Result<usize, NfsError> {
        if let nfs_argop4::OP_WRITE(write_args) = op {
            if let DataPayload::DataRef(data_ref) = write_args.data {
                let padded_data_ref_len = get_padded_size(data_ref.len);
                return Ok(OPS_CODE_SIZE
                    + WRITE4ARGS_FIXED_SIZE_BEFORE_PAYLOAD
                    + padded_data_ref_len
                    + size_of::<uint32_t>());
            }
        }

        // Use a pre-allocated buffer to dummy pack the operation.
        match op.pack(buf) {
            Ok(size) => Ok(size),
            Err(_) => Err(NfsError::EncodeError),
        }
    }
}

impl GetOpSerializedSize for nfs_resop4 {
    fn get_op_serialized_size(op: &nfs_resop4, buf: &mut Vec<u8>) -> Result<usize, NfsError> {
        if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_res))
        | nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(read_res)) = op
        {
            if let DataPayload::DataRef(data_ref) = read_res.data {
                let padded_data_ref_len = get_padded_size(data_ref.len);
                return Ok(OPS_CODE_SIZE
                    + READ4RES_FIXED_SIZE_BEFORE_PAYLOAD
                    + padded_data_ref_len
                    + size_of::<uint32_t>());
            }
        }
        match op.pack(buf) {
            Ok(size) => Ok(size),
            Err(_) => Err(NfsError::EncodeError),
        }
    }
}

impl GetOpSerializedSize for nfs_cb_argop4 {
    fn get_op_serialized_size(op: &nfs_cb_argop4, buf: &mut Vec<u8>) -> Result<usize, NfsError> {
        match op.pack(buf) {
            Ok(size) => Ok(size),
            Err(_) => Err(NfsError::EncodeError),
        }
    }
}
impl GetOpSerializedSize for nfs_cb_resop4 {
    fn get_op_serialized_size(op: &nfs_cb_resop4, buf: &mut Vec<u8>) -> Result<usize, NfsError> {
        match op.pack(buf) {
            Ok(size) => Ok(size),
            Err(_) => Err(NfsError::EncodeError),
        }
    }
}

mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_get_op_serialized_size() {
        let mut buf = Vec::<u8>::with_capacity(1024);

        // Test COMPOUND4args operations
        let compound_args = COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 1,
            argarray: vec![
                // OP_SEQUENCE
                nfs_argop4::OP_SEQUENCE(SEQUENCE4args {
                    sa_sessionid: sessionid4([1; 16]),
                    sa_sequenceid: 1,
                    sa_slotid: 0,
                    sa_highest_slotid: 63,
                    sa_cachethis: false,
                }),
                // OP_WRITE with owned data
                nfs_argop4::OP_WRITE(WRITE4args {
                    stateid: stateid4 {
                        seqid: 1,
                        other: [0; 12],
                    },
                    offset: 0,
                    stable: stable_how4::UNSTABLE4,
                    data: DataPayload::Data(Bytes::from_static(b"test write data")),
                }),
                // OP_WRITE with data ref
                nfs_argop4::OP_WRITE(WRITE4args {
                    stateid: stateid4 {
                        seqid: 1,
                        other: [0; 12],
                    },
                    offset: 0,
                    stable: stable_how4::UNSTABLE4,
                    data: DataPayload::DataRef(OpaqueRaw { len: 14, offset: 0 }),
                }),
                // OP_AWSFILE_READ_BYPASS
                nfs_argop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4args {
                    stateid: stateid4 {
                        seqid: 1,
                        other: [0; 12],
                    },
                    offset: 0,
                    count: 1024,
                }),
            ],
        };

        // Test OP_SEQUENCE size for COMPOUND4args
        buf.clear();
        let sequence_size =
            nfs_argop4::get_op_serialized_size(&compound_args.argarray[0], &mut buf)
                .expect("Failed to get OP_SEQUENCE size");
        assert_eq!(sequence_size, 36, "OP_SEQUENCE size should be 36 bytes");

        // Test OP_WRITE size for COMPOUND4args (with owned data)
        buf.clear();
        let write_size = nfs_argop4::get_op_serialized_size(&compound_args.argarray[1], &mut buf)
            .expect("Failed to get OP_WRITE size");
        assert_eq!(write_size, 52, "OP_WRITE size should be 52 bytes");

        // Test OP_WRITE size for COMPOUND4args (with DataRef)
        buf.clear();
        let write_dataref_size =
            nfs_argop4::get_op_serialized_size(&compound_args.argarray[2], &mut buf)
                .expect("Failed to get OP_WRITE with DataRef size");
        assert_eq!(
            write_dataref_size, 52,
            "OP_WRITE with DataRef size should be 52 bytes"
        );

        // Test OP_AWSFILE_READ_BYPASS size for COMPOUND4args
        buf.clear();
        let read_bypass_size =
            nfs_argop4::get_op_serialized_size(&compound_args.argarray[3], &mut buf)
                .expect("Failed to get OP_AWSFILE_READ_BYPASS size");
        assert_eq!(
            read_bypass_size, 32,
            "OP_AWSFILE_READ_BYPASS size should be 32 bytes"
        );

        // Test COMPOUND4res operations
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![
                // OP_SEQUENCE
                nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(SEQUENCE4resok {
                    sr_sessionid: sessionid4([1; 16]),
                    sr_sequenceid: 1,
                    sr_slotid: 0,
                    sr_highest_slotid: 63,
                    sr_target_highest_slotid: 63,
                    sr_status_flags: 0,
                })),
                // OP_WRITE
                nfs_resop4::OP_WRITE(WRITE4res::NFS4_OK(WRITE4resok {
                    count: 15,
                    committed: stable_how4::UNSTABLE4,
                    writeverf: verifier4([0; 8]),
                })),
                // OP_READ with owned data
                nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
                    eof: false,
                    data: DataPayload::Data(Bytes::from_static(b"test read data")),
                })),
                // OP_READ with DataRef
                nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
                    eof: false,
                    data: DataPayload::DataRef(OpaqueRaw { len: 14, offset: 0 }),
                })),
                // OP_AWSFILE_READ_BYPASS with READ4resok
                nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
                    eof: false,
                    data: DataPayload::Data(Bytes::from_static(b"test read data")),
                })),
                // OP_AWSFILE_READ_BYPASS with READ4resok with DataRef
                nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
                    eof: false,
                    data: DataPayload::DataRef(OpaqueRaw { len: 14, offset: 0 }),
                })),
            ],
        };

        // Test OP_SEQUENCE size for COMPOUND4res
        buf.clear();
        let sequence_res_size =
            nfs_resop4::get_op_serialized_size(&compound_res.resarray[0], &mut buf)
                .expect("Failed to get OP_SEQUENCE response size");
        assert_eq!(
            sequence_res_size, 44,
            "OP_SEQUENCE response size should be 44 bytes"
        );

        // Test OP_WRITE size for COMPOUND4res
        buf.clear();
        let write_res_size =
            nfs_resop4::get_op_serialized_size(&compound_res.resarray[1], &mut buf)
                .expect("Failed to get OP_WRITE response size");
        assert_eq!(
            write_res_size, 24,
            "OP_WRITE response size should be 24 bytes"
        );

        // Test OP_READ size for COMPOUND4res (with owned data)
        buf.clear();
        let read_res_size = nfs_resop4::get_op_serialized_size(&compound_res.resarray[2], &mut buf)
            .expect("Failed to get OP_READ response size");
        assert_eq!(
            read_res_size, 32,
            "OP_READ response size should be 32 bytes"
        );

        // Test OP_READ size for COMPOUND4res (with DataRef)
        buf.clear();
        let read_dataref_res_size =
            nfs_resop4::get_op_serialized_size(&compound_res.resarray[3], &mut buf)
                .expect("Failed to get OP_READ with DataRef response size");
        assert_eq!(
            read_dataref_res_size, 32,
            "OP_READ with DataRef response size should be 40 bytes"
        );

        // Test OP_AWSFILE_READ_BYPASS size for COMPOUND4res
        buf.clear();
        let read_bypass_res_size =
            nfs_resop4::get_op_serialized_size(&compound_res.resarray[4], &mut buf)
                .expect("Failed to get OP_AWSFILE_READ_BYPASS response size");
        assert_eq!(
            read_bypass_res_size, 32,
            "OP_AWSFILE_READ_BYPASS response size should be 32 bytes"
        );

        // Test OP_AWSFILE_READ_BYPASS with data ref
        buf.clear();
        let read_bypass_dataref_res_size =
            nfs_resop4::get_op_serialized_size(&compound_res.resarray[5], &mut buf)
                .expect("Failed to get OP_AWSFILE_READ_BYPASS with DataRef response size");
        assert_eq!(
            read_bypass_dataref_res_size, 32,
            "OP_AWSFILE_READ_BYPASS with DataRef response size should be 32 bytes"
        );

        // Test CB_COMPOUND4args operations
        let cb_compound_args = CB_COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 1,
            callback_ident: 12345,
            argarray: vec![nfs_cb_argop4::OP_CB_SEQUENCE(CB_SEQUENCE4args {
                csa_sessionid: sessionid4([1; 16]),
                csa_sequenceid: 1,
                csa_slotid: 0,
                csa_highest_slotid: 63,
                csa_cachethis: false,
                csa_referring_call_lists: vec![],
            })],
        };

        // Test CB_SEQUENCE size for CB_COMPOUND4args
        buf.clear();
        let cb_sequence_size =
            nfs_cb_argop4::get_op_serialized_size(&cb_compound_args.argarray[0], &mut buf)
                .expect("Failed to get CB_SEQUENCE size");
        assert_eq!(cb_sequence_size, 40, "CB_SEQUENCE size should be 40 bytes");

        // Test CB_COMPOUND4res operations
        let cb_compound_res = CB_COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![nfs_cb_resop4::OP_CB_SEQUENCE(CB_SEQUENCE4res::NFS4_OK(
                CB_SEQUENCE4resok {
                    csr_sessionid: sessionid4([1; 16]),
                    csr_sequenceid: 1,
                    csr_slotid: 0,
                    csr_highest_slotid: 63,
                    csr_target_highest_slotid: 63,
                },
            ))],
        };

        // Test CB_SEQUENCE size for CB_COMPOUND4res
        buf.clear();
        let cb_sequence_res_size =
            nfs_cb_resop4::get_op_serialized_size(&cb_compound_res.resarray[0], &mut buf)
                .expect("Failed to get CB_SEQUENCE response size");
        assert_eq!(
            cb_sequence_res_size, 40,
            "CB_SEQUENCE response size should be 40 bytes"
        );

        // Verify size relationships
        assert!(
            write_size > sequence_size,
            "OP_WRITE should be larger than OP_SEQUENCE due to data payload"
        );
        assert!(
            read_res_size > write_res_size,
            "OP_READ response should be larger than OP_WRITE response due to data payload"
        );
        assert_eq!(
            write_size, write_dataref_size,
            "OP_WRITE with owned data and DataRef should have same serialized size"
        );
    }
}
