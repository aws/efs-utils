// Using #[allow(dead_code)] is a common and acceptable practice for test utility functions.
#![allow(dead_code)]

use crate::{
    nfs::{
        nfs4_1_xdr::*,
        nfs_compound::{NfsCompoundMessage, RefNfsCompoundInfo},
        nfs_parser::NfsMessageParser,
        nfs_rpc_envelope::{NfsRpcEnvelope, NfsRpcInfo},
    },
    rpc::{
        rpc::NFS_PROGRAM,
        rpc_encoder::RpcEncoder,
        rpc_envelope::{RpcCallParams, RpcMessageParams, RpcMessageType, RpcReplyParams},
    },
};
use bytes::{Bytes, BytesMut};
use core::option::Option::None;
use onc_rpc::{auth::AuthFlavor, CallBody, MessageType, RpcMessage};
use xdr_codec::Pack;

use super::{
    nfs4_1_xdr::{
        channel_attrs4, nfs_resop4, nfsstat4, verifier4, COMPOUND4res, CREATE_SESSION4args,
        SEQUENCE4res, WRITE4res,
    },
    nfs4_1_xdr_ext::opnum_from_argop,
    nfs_compound::{NfsMetadata, PackableNfsCompoundInfo},
};

const TEST_NFS_PROCEDURE: u32 = 1;

fn get_sample_sequence_op() -> nfs_argop4 {
    nfs_argop4::OP_SEQUENCE(SEQUENCE4args {
        sa_sessionid: create_test_session_id(),
        sa_sequenceid: 123,
        sa_slotid: 456,
        sa_highest_slotid: 789,
        sa_cachethis: true,
    })
}

fn get_sample_getattr_op() -> nfs_argop4 {
    nfs_argop4::OP_GETATTR(GETATTR4args {
        attr_request: bitmap4(vec![1, 2, 3]),
    })
}

fn get_sample_write_op() -> nfs_argop4 {
    nfs_argop4::OP_WRITE(WRITE4args {
        stateid: stateid4 {
            seqid: 789,
            other: [0xef; 12],
        },
        stable: stable_how4::DATA_SYNC4,
        offset: 8192,
        data: DataPayload::Data(Bytes::from_static(b"Data within a compound request.")),
    })
}

pub fn get_sample_op_sequence_res() -> nfs_resop4 {
    nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(SEQUENCE4resok {
        sr_sessionid: sessionid4([0; 16]),
        sr_sequenceid: 123,
        sr_slotid: 456,
        sr_highest_slotid: 789,
        sr_target_highest_slotid: 789,
        sr_status_flags: 0,
    }))
}

pub fn get_sample_op_getattr_res() -> nfs_resop4 {
    nfs_resop4::OP_GETATTR(GETATTR4res::NFS4_OK(GETATTR4resok {
        obj_attributes: fattr4 {
            attrmask: bitmap4(vec![1, 2, 3]),
            attr_vals: attrlist4(vec![1, 2, 3]),
        },
    }))
}

pub fn get_sample_op_lookup_res() -> nfs_resop4 {
    nfs_resop4::OP_LOOKUP(LOOKUP4res {
        status: nfsstat4::NFS4_OK,
    })
}

pub fn get_sample_op_write_res() -> nfs_resop4 {
    nfs_resop4::OP_WRITE(WRITE4res::NFS4_OK(WRITE4resok {
        count: 123,
        committed: stable_how4::DATA_SYNC4,
        writeverf: verifier4([0xef; 8]),
    }))
}

pub fn get_sample_op_read_bypass_rejected_res(efs_data: Bytes) -> nfs_resop4 {
    nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
        eof: true,
        data: DataPayload::Data(efs_data),
    }))
}

pub fn get_sample_op_read_bypass_resok(
    offset: u64,
    count: u32,
    file_size: u64,
) -> AWSFILE_READ_BYPASS4res {
    AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(AWSFILE_READ_BYPASS4resok {
        filehandle: nfs_fh4(vec![0xef; 16]),
        data_locator: awsfile_bypass_data_locator {
            bucket_name: vec![0xef; 16],
            s3_key: vec![0xef; 16],
            etag: vec![0xef; 16],
            version_id: vec![],
            offset,
            count,
        },
        file_size,
    })
}

pub fn get_sample_op_read_bypass_accepted_res(
    offset: u64,
    count: u32,
    file_size: u64,
) -> nfs_resop4 {
    nfs_resop4::OP_AWSFILE_READ_BYPASS(get_sample_op_read_bypass_resok(offset, count, file_size))
}

pub fn get_sample_op_read_args() -> nfs_argop4 {
    nfs_argop4::OP_READ(READ4args {
        stateid: stateid4 {
            seqid: 789,
            other: [0xef; 12],
        },
        offset: 123,
        count: 123,
    })
}

pub fn get_sample_op_read_bypass_args(offset: u64, count: u32) -> nfs_argop4 {
    nfs_argop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4args {
        stateid: stateid4 {
            seqid: 789,
            other: [0xef; 12],
        },
        offset,
        count,
    })
}

pub fn get_sample_compound_res() -> COMPOUND4res {
    COMPOUND4res {
        status: nfsstat4::NFS4_OK,
        tag: utf8string(b"test_compound_res".to_vec()),
        resarray: vec![
            get_sample_op_sequence_res(),
            get_sample_op_getattr_res(),
            get_sample_op_lookup_res(),
            get_sample_op_write_res(),
        ],
    }
}

pub fn get_sample_compound_res_with_read_payload() -> COMPOUND4res {
    COMPOUND4res {
        status: nfsstat4::NFS4_OK,
        tag: utf8string(b"test_compound_res".to_vec()),
        resarray: vec![
            get_sample_op_sequence_res(),
            get_sample_op_getattr_res(),
            get_sample_op_read_res_with_data(),
            get_sample_op_lookup_res(),
            get_sample_op_write_res(),
        ],
    }
}

pub fn get_sample_op_sequnce_args() -> nfs_argop4 {
    nfs_argop4::OP_SEQUENCE(SEQUENCE4args {
        sa_sessionid: create_test_session_id(),
        sa_sequenceid: 123,
        sa_slotid: 456,
        sa_highest_slotid: 789,
        sa_cachethis: true,
    })
}

pub fn get_sample_op_getattr_args() -> nfs_argop4 {
    nfs_argop4::OP_GETATTR(GETATTR4args {
        attr_request: bitmap4(vec![1, 2, 3]),
    })
}

pub fn get_sample_compound_res_with_multiple_read_bypass_res() -> COMPOUND4res {
    COMPOUND4res {
        status: nfsstat4::NFS4_OK,
        tag: utf8string(b"test_compound_res".to_vec()),
        resarray: vec![
            get_sample_op_sequence_res(),
            get_sample_op_getattr_res(),
            get_sample_op_read_res_with_data(),
            get_sample_put_fh_res(),
            get_sample_op_read_bypass_rejected_res(Bytes::from_static(
                b"Data within a compound request.",
            )),
            get_sample_op_read_bypass_rejected_res(Bytes::from_static(
                b"Data within a compound request.",
            )),
        ],
    }
}

pub fn get_sample_put_fh_res() -> nfs_resop4 {
    nfs_resop4::OP_PUTFH(PUTFH4res {
        status: nfsstat4::NFS4_OK,
    })
}

pub fn get_sample_put_fh_args() -> nfs_argop4 {
    nfs_argop4::OP_PUTFH(PUTFH4args {
        object: nfs_fh4(vec![0xef; 16]),
    })
}

pub fn get_sample_compound_args_with_multiple_read_args() -> COMPOUND4args {
    COMPOUND4args {
        tag: utf8string(b"test_compound_args".to_vec()),
        minorversion: 1,
        argarray: vec![
            get_sample_op_sequnce_args(),
            get_sample_op_getattr_args(),
            get_sample_op_read_args(),
            get_sample_put_fh_args(),
            get_sample_op_read_args(),
            get_sample_op_read_args(),
        ],
    }
}

pub fn get_sample_op_read_res_with_data() -> nfs_resop4 {
    nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
        eof: true,
        data: DataPayload::Data(Bytes::from_static(b"Data within a compound request.")),
    }))
}

pub fn create_basic_test_compound_args() -> COMPOUND4args {
    let sequence_op = get_sample_sequence_op();
    let getattr_op = get_sample_getattr_op();

    COMPOUND4args {
        tag: utf8string(b"test_tag".to_vec()), // Added a non-empty tag for clarity
        minorversion: 1,
        argarray: vec![sequence_op, getattr_op],
    }
}

pub fn create_test_compound_args_with_write_args_no_ref() -> COMPOUND4args {
    let mut basic_compound = create_basic_test_compound_args();
    let write_op = get_sample_write_op();

    basic_compound.argarray.push(write_op);
    basic_compound
}

pub fn create_test_compound_res() -> COMPOUND4res {
    let op_seq_res = SEQUENCE4resok {
        sr_highest_slotid: 789,
        sr_slotid: 456,
        sr_sequenceid: 123,
        sr_sessionid: create_test_session_id(),
        sr_target_highest_slotid: 789,
        sr_status_flags: 0,
    };
    let op_write_res = WRITE4resok {
        count: 123,
        committed: stable_how4::DATA_SYNC4,
        writeverf: verifier4([0xef; 8]),
    };

    COMPOUND4res {
        status: nfsstat4::NFS4_OK,
        tag: utf8string(b"test_tag".to_vec()),
        resarray: vec![
            nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(op_seq_res)),
            nfs_resop4::OP_WRITE(WRITE4res::NFS4_OK(op_write_res)),
        ],
    }
}

pub const BTYES_BEFORE_WRITE4ARGS_DATA_BUFFER: usize = 32;

pub fn create_test_compound_args_with_write_args_with_ref(
    payload: &Bytes,
) -> (COMPOUND4args, BytesMut) {
    let mut basic_compound = create_basic_test_compound_args();
    let mut raw_bytes = Vec::new();
    basic_compound
        .pack(&mut raw_bytes)
        .expect("Failed to pack basic compound");
    let length_of_basic_compound = raw_bytes.len();
    let mut compound_no_ref = basic_compound.clone();
    let write_op_data = payload.clone();
    let data_ref = OpaqueRaw {
        offset: length_of_basic_compound + BTYES_BEFORE_WRITE4ARGS_DATA_BUFFER + 4, // 32 is the length of the write op fields before opaque data, 4 is the length of the write_op code
        len: write_op_data.len(),
    };
    let write_op = nfs_argop4::OP_WRITE(WRITE4args {
        stateid: stateid4 {
            seqid: 789,
            other: [0xef; 12],
        },
        stable: stable_how4::DATA_SYNC4,
        offset: 8192,
        data: DataPayload::DataRef(data_ref),
    });

    basic_compound.argarray.push(write_op);

    // construct a raw bytes for the ref compound:
    let write_op_no_ref = nfs_argop4::OP_WRITE(WRITE4args {
        stateid: stateid4 {
            seqid: 789,
            other: [0xef; 12],
        },
        stable: stable_how4::DATA_SYNC4,
        offset: 8192,
        data: DataPayload::Data(write_op_data),
    });
    compound_no_ref.argarray.push(write_op_no_ref);
    let mut raw_bytes_after_adding_write_no_ref = Vec::new();
    compound_no_ref
        .pack(&mut raw_bytes_after_adding_write_no_ref)
        .expect("Failed to pack basic compound");
    let raw_bytes_after_adding_write_no_ref =
        BytesMut::from(&raw_bytes_after_adding_write_no_ref[..]);

    (basic_compound, raw_bytes_after_adding_write_no_ref)
}

pub fn create_test_op_sequence_arg() -> nfs_argop4 {
    nfs_argop4::OP_SEQUENCE(SEQUENCE4args {
        sa_sessionid: create_test_session_id(),
        sa_sequenceid: 123,
        sa_slotid: 456,
        sa_highest_slotid: 789,
        sa_cachethis: true,
    })
}
pub fn create_test_session_id() -> sessionid4 {
    let mut id_bytes = [0u8; 16];
    for (i, item) in id_bytes.iter_mut().enumerate() {
        *item = (i + 1) as u8;
    }
    sessionid4(id_bytes)
}

const DEFAULT_CHANNEL_ATTRS: channel_attrs4 = channel_attrs4 {
    ca_headerpadsize: 1024,
    ca_maxrequestsize: 1024,
    ca_maxresponsesize: 1024,
    ca_maxresponsesize_cached: 1024,
    ca_maxoperations: 1024,
    ca_maxrequests: 1024,
    ca_rdma_ird: vec![],
};

pub fn create_test_create_session_arg() -> nfs_argop4 {
    nfs_argop4::OP_CREATE_SESSION(CREATE_SESSION4args {
        csa_clientid: 1234_u64,
        csa_sequence: 1234_u32,
        csa_flags: 0,
        csa_fore_chan_attrs: DEFAULT_CHANNEL_ATTRS,
        csa_back_chan_attrs: DEFAULT_CHANNEL_ATTRS,
        csa_cb_program: 0,
        csa_sec_parms: vec![],
    })
}

pub fn create_test_create_session_res() -> nfs_resop4 {
    nfs_resop4::OP_CREATE_SESSION(CREATE_SESSION4res::NFS4_OK(CREATE_SESSION4resok {
        csr_sessionid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        csr_sequence: 1234_u32,
        csr_flags: 0,
        csr_fore_chan_attrs: DEFAULT_CHANNEL_ATTRS,
        csr_back_chan_attrs: DEFAULT_CHANNEL_ATTRS,
    }))
}

pub fn create_test_exchange_id_arg() -> nfs_argop4 {
    nfs_argop4::OP_EXCHANGE_ID(EXCHANGE_ID4args {
        eia_clientowner: client_owner4 {
            co_verifier: verifier4([1, 2, 3, 4, 5, 6, 7, 8]),
            co_ownerid: vec![1, 2, 3, 4],
        },
        eia_flags: 0,
        eia_state_protect: state_protect4_a::SP4_NONE,
        eia_client_impl_id: vec![],
    })
}

pub fn create_test_exchange_id_res() -> nfs_resop4 {
    nfs_resop4::OP_EXCHANGE_ID(EXCHANGE_ID4res::NFS4_OK(EXCHANGE_ID4resok {
        eir_clientid: 1234_u64,
        eir_sequenceid: 1234_u32,
        eir_flags: 0,
        eir_state_protect: state_protect4_r::SP4_NONE,
        eir_server_owner: server_owner4 {
            so_minor_id: 0,
            so_major_id: vec![1, 2, 3, 4],
        },
        eir_server_scope: vec![5, 6, 7, 8],
        eir_server_impl_id: vec![],
    }))
}

pub fn create_test_bind_conn_to_session_arg() -> nfs_argop4 {
    nfs_argop4::OP_BIND_CONN_TO_SESSION(BIND_CONN_TO_SESSION4args {
        bctsa_sessid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        bctsa_dir: channel_dir_from_client4::CDFC4_FORE,
        bctsa_use_conn_in_rdma_mode: false,
    })
}

pub fn create_test_bind_conn_to_session_res() -> nfs_resop4 {
    nfs_resop4::OP_BIND_CONN_TO_SESSION(BIND_CONN_TO_SESSION4res::NFS4_OK(
        BIND_CONN_TO_SESSION4resok {
            bctsr_sessid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            bctsr_dir: channel_dir_from_server4::CDFS4_FORE,
            bctsr_use_conn_in_rdma_mode: false,
        },
    ))
}

pub fn create_test_destroy_session_arg() -> nfs_argop4 {
    nfs_argop4::OP_DESTROY_SESSION(DESTROY_SESSION4args {
        dsa_sessionid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
    })
}

pub fn create_test_destroy_session_res() -> nfs_resop4 {
    nfs_resop4::OP_DESTROY_SESSION(DESTROY_SESSION4res {
        dsr_status: nfsstat4::NFS4_OK,
    })
}

pub fn create_test_destroy_clientid_arg() -> nfs_argop4 {
    nfs_argop4::OP_DESTROY_CLIENTID(DESTROY_CLIENTID4args {
        dca_clientid: 1234_u64,
    })
}

pub fn create_test_destroy_clientid_res() -> nfs_resop4 {
    nfs_resop4::OP_DESTROY_CLIENTID(DESTROY_CLIENTID4res {
        dcr_status: nfsstat4::NFS4_OK,
    })
}

pub fn create_test_packable_compound_info_with_arg_vec(
    arg_vec: Vec<nfs_argop4>,
) -> PackableNfsCompoundInfo<COMPOUND4args> {
    PackableNfsCompoundInfo {
        nfs_metadata: NfsMetadata {
            session_id: create_test_session_id(),
            slot_id: 456,
            sequence_id: 123,
        },
        op_vec: arg_vec.iter().map(opnum_from_argop).collect(),
        compound: COMPOUND4args {
            tag: utf8string(b"test_tag".to_vec()),
            minorversion: 1,
            argarray: arg_vec,
        },
    }
}

pub fn create_default_rpc_message_from_payload(payload: &[u8]) -> RpcMessage<&[u8], &[u8]> {
    let call_body = CallBody::new(
        NFS_PROGRAM,
        4,
        1,
        AuthFlavor::AuthNone(None),
        AuthFlavor::AuthNone(None),
        payload,
    );
    RpcMessage::new(123, MessageType::Call(call_body))
}

pub fn create_rpc_message_and_nfs_payload_from_compound_args(
    compound_args: COMPOUND4args,
    output_payload: &mut Vec<u8>,
) -> RpcMessage<&[u8], &[u8]> {
    compound_args
        .pack(output_payload)
        .expect("Failed to pack compound args");
    let rpc_message = create_default_rpc_message_from_payload(output_payload);
    rpc_message
}

pub fn create_basic_test_compound_res() -> COMPOUND4res {
    let op_seq_res = SEQUENCE4resok {
        sr_highest_slotid: 789,
        sr_slotid: 456,
        sr_sequenceid: 123,
        sr_sessionid: create_test_session_id(),
        sr_target_highest_slotid: 789,
        sr_status_flags: 0,
    };
    let op_write_res = WRITE4resok {
        count: 123,
        committed: stable_how4::DATA_SYNC4,
        writeverf: verifier4([0xef; 8]),
    };

    COMPOUND4res {
        status: nfsstat4::NFS4_OK,
        tag: utf8string(b"test_tag".to_vec()),
        resarray: vec![
            nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(op_seq_res)),
            nfs_resop4::OP_WRITE(WRITE4res::NFS4_OK(op_write_res)),
        ],
    }
}

pub fn create_test_compound_res_with_read_res_no_ref() -> COMPOUND4res {
    let mut basic_compound_res = create_basic_test_compound_res();

    let read_resok = READ4resok {
        eof: true,
        data: DataPayload::Data(Bytes::from_static(b"Data within a compound request.")),
    };
    let read_op_res = nfs_resop4::OP_READ(READ4res::NFS4_OK(read_resok));

    basic_compound_res.resarray.push(read_op_res);
    basic_compound_res
}

pub const BTYES_BEFORE_READ4RES_DATA_BUFFER: usize = 12;

pub fn create_test_compound_res_with_read_res_with_ref(
    payload: &Bytes,
) -> (COMPOUND4res, BytesMut) {
    let mut basic_compound_res = create_basic_test_compound_res();
    let mut raw_bytes = Vec::new();
    basic_compound_res
        .pack(&mut raw_bytes)
        .expect("Failed to pack basic compound res");
    let read_op_data = payload.clone();
    let length_of_basic_compound_res = raw_bytes.len();
    let mut compound_no_ref = basic_compound_res.clone();
    let data_ref = OpaqueRaw {
        offset: length_of_basic_compound_res + BTYES_BEFORE_READ4RES_DATA_BUFFER + 4, // 12 is the length of the read op fields before opaque data, 4 is the length of the read_op code
        len: read_op_data.len(),
    };
    let read_resok = READ4resok {
        eof: true,
        data: DataPayload::DataRef(data_ref),
    };
    let read_op_res = nfs_resop4::OP_READ(READ4res::NFS4_OK(read_resok));

    basic_compound_res.resarray.push(read_op_res);

    // construct a raw bytes for the ref compound:
    let read_resok_no_ref = READ4resok {
        eof: true,
        data: DataPayload::Data(read_op_data),
    };
    let read_op_no_ref = nfs_resop4::OP_READ(READ4res::NFS4_OK(read_resok_no_ref));

    compound_no_ref.resarray.push(read_op_no_ref);
    let mut raw_bytes_after_adding_read_no_ref = Vec::new();
    compound_no_ref
        .pack(&mut raw_bytes_after_adding_read_no_ref)
        .expect("Failed to pack basic compound");
    let raw_bytes_after_adding_read_no_ref =
        BytesMut::from(&raw_bytes_after_adding_read_no_ref[..]);

    (basic_compound_res, raw_bytes_after_adding_read_no_ref)
}

pub fn create_rpc_reply_message_from_compound_res(
    compound_res: COMPOUND4res,
) -> RpcMessage<BytesMut, BytesMut> {
    let mut buffer = Vec::new();
    compound_res
        .pack(&mut buffer)
        .expect("Failed to pack compound res");

    let payload = BytesMut::from(buffer.as_slice());
    let reply_body = onc_rpc::ReplyBody::Accepted(onc_rpc::AcceptedReply::new(
        AuthFlavor::AuthNone(None),
        onc_rpc::AcceptedStatus::Success(payload.clone()),
    ));

    RpcMessage::new(123, MessageType::Reply(reply_body))
}

pub fn create_compound_args_raw_bytes() -> BytesMut {
    let mut buffer = Vec::new();
    let compound_args = create_test_compound_args_with_write_args_no_ref();
    compound_args
        .pack(&mut buffer)
        .expect("Failed to pack compound args");
    BytesMut::from(&buffer[..])
}

pub fn create_basic_compound_args_ref_info() -> RefNfsCompoundInfo<COMPOUND4args> {
    let compound_args = create_compound_args_raw_bytes();
    NfsMessageParser::parse_compound::<COMPOUND4args>(compound_args)
        .expect("Failed to parse compound args")
}

pub fn build_read_nfs_compound_args(
    file_handle: &nfs_fh4,
    read_offset: u64,
    read_len: u32,
) -> COMPOUND4args {
    // Build compound: SEQUENCE, PUTFH, READ
    let sequence_op = create_test_op_sequence_arg();
    let putfh_op = nfs_argop4::OP_PUTFH(PUTFH4args {
        object: file_handle.clone().into(),
    });
    let read_op = nfs_argop4::OP_READ(READ4args {
        stateid: stateid4 {
            seqid: 1,
            other: [0; 12],
        },
        offset: read_offset,
        count: read_len,
    });
    let compound = COMPOUND4args {
        tag: utf8string(b"test".to_vec()),
        minorversion: 1,
        argarray: vec![sequence_op, putfh_op, read_op],
    };
    compound
}

pub fn create_raw_bytes_for_rpc_nfs_message_from_compound<
    CompoundType: NfsCompoundMessage<OpCodeType = nfs_opnum4> + Pack<Vec<u8>>,
>(
    rpc_message_type: RpcMessageType,
    compound_args: CompoundType,
) -> BytesMut {
    let xid = 1;
    let params = match rpc_message_type {
        RpcMessageType::Call => RpcMessageParams::CallParams(RpcCallParams {
            xid,
            program_id: NFS_PROGRAM,
            program_version: 0,
            procedure: TEST_NFS_PROCEDURE,
            auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }),
        RpcMessageType::Reply => RpcMessageParams::ReplyParams(RpcReplyParams {
            xid: 1,
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }),
    };

    let mut buffer = Vec::new();
    compound_args
        .pack(&mut buffer)
        .expect("Failed to pack compound args");
    let payload = BytesMut::from(&buffer[..]);

    match rpc_message_type {
        RpcMessageType::Call => {
            return RpcEncoder::encode_rpc_call_with_payload(params, payload)
                .unwrap()
                .into();
        }
        RpcMessageType::Reply => {
            return RpcEncoder::encode_rpc_accepted_reply_with_payload(xid, params, payload)
                .unwrap()
                .into();
        }
    };
}

pub fn create_nfs_rpc_envelope_from_compound<
    CompoundType: NfsCompoundMessage<OpCodeType = nfs_opnum4> + Pack<Vec<u8>>,
>(
    rpc_message_type: RpcMessageType,
    compound_args: CompoundType,
) -> NfsRpcEnvelope {
    let serialized_message =
        create_raw_bytes_for_rpc_nfs_message_from_compound(rpc_message_type, compound_args);
    NfsRpcEnvelope::try_from(serialized_message).unwrap()
}

pub fn create_nfs_rpc_envelope_batch_from_compound<
    CompoundType: NfsCompoundMessage<OpCodeType = nfs_opnum4> + Pack<Vec<u8>>,
>(
    rpc_message_type: RpcMessageType,
    compound_args: CompoundType,
) -> NfsRpcInfo {
    let nfs_rpc_envelope = create_nfs_rpc_envelope_from_compound(rpc_message_type, compound_args);
    NfsRpcInfo {
        envelopes: vec![nfs_rpc_envelope],
    }
}

pub fn get_read_payload_from_ref_compound(
    ref_compound: &RefNfsCompoundInfo<COMPOUND4res>,
) -> Bytes {
    let data_payload = ref_compound
        .compound
        .resarray
        .iter()
        .find_map(|r| match r {
            nfs_resop4::OP_READ(READ4res::NFS4_OK(res)) => Some(&res.data),
            _ => None,
        })
        .expect("No read operation found in NFS compound");

    match data_payload {
        DataPayload::DataRef(data_ref) => Bytes::from(
            ref_compound.get_nfs_message()[data_ref.offset..data_ref.offset + data_ref.len]
                .to_vec(),
        ),
        DataPayload::Data(_) => panic!("DataPayload::Data is not supported"),
    }
}

// Ensure that testing utils work as expected ("Tests for tests")
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nfs::nfs_compound::RefNfsCompound, rpc::rpc::RpcBatch};

    #[tokio::test]
    async fn test_create_nfs_rpc_envelope_from_compound() {
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        };

        let envelope =
            create_nfs_rpc_envelope_from_compound(RpcMessageType::Reply, compound_res.clone());

        let message = NfsRpcInfo {
            envelopes: vec![envelope],
        };

        let rpc_batch: RpcBatch = message.into();
        let rpc_envelope = &rpc_batch.rpcs[0];
        let res = NfsRpcEnvelope::try_from(rpc_envelope.clone());
        assert!(res.is_ok());
        let nfs_rpc_envelope = res.unwrap();
        if let RefNfsCompound::Compound4res(nfs_res_compound) = &nfs_rpc_envelope.body {
            assert_eq!(nfs_res_compound.compound.resarray, compound_res.resarray);
        } else {
            panic!("Unexpected compound type");
        }
    }
}
