#![allow(unused)]

use crate::nfs::error::NfsError;
use crate::nfs::nfs4_1_xdr::COMPOUND4args;
use crate::nfs::nfs_compound::{
    NfsCompoundMessage, NfsMetadata, PackableNfsCompoundInfo, RefNfsCompoundInfo,
};
use bytes::BytesMut;
use log::{debug, trace, warn};
use std::io::Cursor;
use xdr_codec::{Pack, Unpack};

use super::nfs4_1_xdr::{CB_COMPOUND4args, CB_COMPOUND4res, COMPOUND4res};
use super::nfs_compound::{NfsCompoundType, RefNfsCompound};

pub struct NfsMessageParser;

impl NfsMessageParser {
    pub fn parse_compound<
        T: NfsCompoundMessage + for<'a> Unpack<Cursor<&'a [u8]>> + for<'a> Pack<&'a mut [u8]>,
    >(
        nfs_payload: BytesMut,
    ) -> Result<RefNfsCompoundInfo<T>, NfsError> {
        trace!("NfsPayload length: {}", nfs_payload.len());

        let mut cursor = Cursor::new(nfs_payload.as_ref());
        let (compound, _) = match T::unpack(&mut cursor) {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "NfsCompound parse error during unpack: {:?}, payload_len: {}, first_32_bytes: {:?}",
                    NfsError::ParseError,
                    nfs_payload.len(),
                    &nfs_payload.as_ref()[..nfs_payload.len().min(255)]
                );
                debug!("NfsCompound parse error payload: {:?}", nfs_payload);
                return Err(NfsError::ParseError);
            }
        };

        let nfs_metadata = compound.extract_metadata();

        let op_vec = compound.extract_opcode_vec();

        trace!("NfsMetadata: {:?}, OpVec: {:?}", nfs_metadata, op_vec);

        Ok(RefNfsCompoundInfo::new(
            nfs_metadata,
            compound,
            op_vec,
            nfs_payload,
        ))
    }

    pub fn parse_packable_compound<
        T: NfsCompoundMessage + for<'a> Unpack<Cursor<&'a [u8]>> + for<'a> Pack<&'a mut [u8]>,
    >(
        nfs_payload: BytesMut,
    ) -> Result<PackableNfsCompoundInfo<T>, NfsError> {
        let ref_compound_info = Self::parse_compound::<T>(nfs_payload)?;
        Ok(ref_compound_info.into_packable_info())
    }

    pub fn parse_from_rpc_payload(
        body_type: NfsCompoundType,
        body_bytes_mut: BytesMut,
    ) -> Result<RefNfsCompound, NfsError> {
        match body_type {
            NfsCompoundType::Compound4args => {
                let compound = NfsMessageParser::parse_compound::<COMPOUND4args>(body_bytes_mut)?;
                Ok(RefNfsCompound::Compound4args(compound))
            }
            NfsCompoundType::Compound4res => {
                let compound = NfsMessageParser::parse_compound::<COMPOUND4res>(body_bytes_mut)?;
                Ok(RefNfsCompound::Compound4res(compound))
            }
            NfsCompoundType::CbCompound4args => {
                let compound =
                    NfsMessageParser::parse_compound::<CB_COMPOUND4args>(body_bytes_mut)?;
                Ok(RefNfsCompound::CbCompound4args(compound))
            }
            NfsCompoundType::CbCompound4res => {
                let compound = NfsMessageParser::parse_compound::<CB_COMPOUND4res>(body_bytes_mut)?;
                Ok(RefNfsCompound::CbCompound4res(compound))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::{nfs4_1_xdr::*, nfs_test_utils::*};
    use bytes::Bytes;
    use xdr_codec::Pack;

    #[test]
    fn test_parse_compound() {
        // Create a SEQUENCE op for the compound
        let sequence_op = nfs_argop4::OP_SEQUENCE(SEQUENCE4args {
            sa_sessionid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            sa_sequenceid: 123,
            sa_slotid: 456,
            sa_highest_slotid: 789,
            sa_cachethis: true,
        });

        // Create a GETATTR op for the compound
        let getattr_op = nfs_argop4::OP_GETATTR(GETATTR4args {
            attr_request: bitmap4(vec![1, 2, 3]),
        });

        // Create the compound args
        let compound_args = COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 1,
            argarray: vec![sequence_op, getattr_op],
        };

        // Pack the args to bytes
        let mut buffer = Vec::<u8>::new();
        compound_args
            .pack(&mut buffer)
            .expect("Failed to pack compound args");
        let buffer_bytes_mut = BytesMut::from(&buffer[..]);
        let buffer_clone = buffer_bytes_mut.clone();

        // Parse the compound
        let result = NfsMessageParser::parse_compound::<COMPOUND4args>(buffer_bytes_mut);

        // Verify the result is RefNfsCompoundInfo
        assert!(
            result.is_ok(),
            "Failed to parse compound: {:?}",
            result.err()
        );

        let nfs_info = result.unwrap();
        assert_eq!(nfs_info.nfs_metadata.slot_id, 456);
        assert_eq!(nfs_info.nfs_metadata.sequence_id, 123);
        assert_eq!(nfs_info.op_vec.len(), 2);

        // check ops vec
        assert_eq!(nfs_info.op_vec[0], nfs_opnum4::OP_SEQUENCE);
        assert_eq!(nfs_info.op_vec[1], nfs_opnum4::OP_GETATTR);

        // Verify the sessionid
        let expected_sessionid =
            sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        for i in 0..16 {
            assert_eq!(
                nfs_info.nfs_metadata.session_id.0[i],
                expected_sessionid.0[i]
            );
        }

        // verify buffer_ref
        assert_eq!(nfs_info.get_nfs_message(), buffer_clone.as_ref());
    }

    #[test]
    fn test_parsing_compound_res() {
        // Import necessary response types
        use crate::nfs::nfs4_1_xdr::{
            attrlist4, bitmap4, fattr4, nfs_resop4, nfsstat4, COMPOUND4res, GETATTR4res,
            GETATTR4resok, SEQUENCE4res, SEQUENCE4resok,
        };

        // Create a SEQUENCE4resok for the compound response
        let sequence_resok = SEQUENCE4resok {
            sr_sessionid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            sr_sequenceid: 234,
            sr_slotid: 567,
            sr_highest_slotid: 890,
            sr_target_highest_slotid: 890, // Assuming target is same as highest for simplicity
            sr_status_flags: 0,            // Assuming OK status
        };
        let sequence_op_res = nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(sequence_resok));

        // Create a GETATTR4resok for the compound response
        let getattr_resok = GETATTR4resok {
            obj_attributes: fattr4 {
                attrmask: bitmap4(vec![4, 5, 6]),
                attr_vals: attrlist4(Vec::new()),
            },
        };
        let getattr_op_res = nfs_resop4::OP_GETATTR(GETATTR4res::NFS4_OK(getattr_resok));

        // Create the compound response
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![sequence_op_res, getattr_op_res],
        };

        // Pack the response to bytes
        let mut buffer = Vec::<u8>::new();
        compound_res
            .pack(&mut buffer)
            .expect("Failed to pack compound res");
        let buffer_bytes_mut = BytesMut::from(&buffer[..]);
        let buffer_clone = buffer_bytes_mut.clone();

        // Parse the compound response
        let result = NfsMessageParser::parse_compound::<COMPOUND4res>(buffer_bytes_mut);

        // Verify the result is RefNfsCompoundInfo
        assert!(
            result.is_ok(),
            "Failed to parse compound_res: {:?}",
            result.err()
        );

        let nfs_info = result.unwrap();
        assert_eq!(nfs_info.nfs_metadata.slot_id, 567);
        assert_eq!(nfs_info.nfs_metadata.sequence_id, 234);
        assert_eq!(nfs_info.op_vec.len(), 2);

        // check ops vec
        assert_eq!(nfs_info.op_vec[0], nfs_opnum4::OP_SEQUENCE);
        assert_eq!(nfs_info.op_vec[1], nfs_opnum4::OP_GETATTR);

        // Verify the sessionid
        let expected_sessionid =
            sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        for i in 0..16 {
            assert_eq!(
                nfs_info.nfs_metadata.session_id.0[i],
                expected_sessionid.0[i]
            );
        }

        // verify buffer_ref
        assert_eq!(nfs_info.get_nfs_message(), buffer_clone.as_ref());
    }

    #[test]
    fn test_parse_xattr_compound() {
        // Import necessary arg types
        use crate::nfs::nfs4_1_xdr::{
            setxattr_option4, xattrvalue4, GETXATTR4args, LISTXATTRS4args, REMOVEXATTR4args,
            SETXATTR4args,
        };

        // Create a SEQUENCE op for the compound
        let sequence_op = nfs_argop4::OP_SEQUENCE(SEQUENCE4args {
            sa_sessionid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            sa_sequenceid: 123,
            sa_slotid: 456,
            sa_highest_slotid: 789,
            sa_cachethis: true,
        });

        // Create a GETXATTR op for the compound
        let getxattr_op = nfs_argop4::OP_GETXATTR(GETXATTR4args {
            gxa_name: utf8string(b"test_name".to_vec()),
        });

        // Create a SETXATTR op for the compound
        let setxattr_op = nfs_argop4::OP_SETXATTR(SETXATTR4args {
            sxa_option: setxattr_option4::SETXATTR4_EITHER,
            sxa_key: utf8string(b"test_name".to_vec()),
            sxa_value: xattrvalue4(Vec::<u8>::new()),
        });

        // Create a LISTXATTRS op for the compound
        let listxattrs_op = nfs_argop4::OP_LISTXATTRS(LISTXATTRS4args {
            lxa_cookie: 123u64,
            lxa_maxcount: 1u32,
        });

        // Create a GETXATTR op for the compound
        let removexattr_op = nfs_argop4::OP_REMOVEXATTR(REMOVEXATTR4args {
            rxa_name: utf8string(b"test_name".to_vec()),
        });

        // Create the compound args
        let compound_args = COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 1,
            argarray: vec![
                sequence_op,
                getxattr_op,
                setxattr_op,
                listxattrs_op,
                removexattr_op,
            ],
        };

        // Pack the args to bytes
        let mut buffer = Vec::<u8>::new();
        compound_args
            .pack(&mut buffer)
            .expect("Failed to pack compound args");
        let buffer_bytes_mut = BytesMut::from(&buffer[..]);
        let buffer_clone = buffer_bytes_mut.clone();

        // Parse the compound
        let result = NfsMessageParser::parse_compound::<COMPOUND4args>(buffer_bytes_mut);

        // Verify the result is RefNfsCompoundInfo
        assert!(
            result.is_ok(),
            "Failed to parse compound: {:?}",
            result.err()
        );

        let nfs_info = result.unwrap();
        assert_eq!(nfs_info.nfs_metadata.slot_id, 456);
        assert_eq!(nfs_info.nfs_metadata.sequence_id, 123);
        assert_eq!(nfs_info.op_vec.len(), 5);

        // check ops vec
        assert_eq!(nfs_info.op_vec[0], nfs_opnum4::OP_SEQUENCE);
        assert_eq!(nfs_info.op_vec[1], nfs_opnum4::OP_GETXATTR);
        assert_eq!(nfs_info.op_vec[2], nfs_opnum4::OP_SETXATTR);
        assert_eq!(nfs_info.op_vec[3], nfs_opnum4::OP_LISTXATTRS);
        assert_eq!(nfs_info.op_vec[4], nfs_opnum4::OP_REMOVEXATTR);

        // Verify the sessionid
        let expected_sessionid =
            sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        for i in 0..16 {
            assert_eq!(
                nfs_info.nfs_metadata.session_id.0[i],
                expected_sessionid.0[i]
            );
        }

        // verify buffer_ref
        assert_eq!(nfs_info.get_nfs_message(), buffer_clone.as_ref());
    }

    #[test]
    fn test_parsing_xattr_compound_res() {
        // Import necessary response types
        use crate::nfs::nfs4_1_xdr::{
            attrlist4, bitmap4, change_info4, fattr4, nfs_resop4, nfsstat4, xattrvalue4,
            COMPOUND4res, GETXATTR4res, LISTXATTRS4res, LISTXATTRS4resok, REMOVEXATTR4res,
            SEQUENCE4res, SEQUENCE4resok, SETXATTR4res,
        };

        // Create a SEQUENCE4resok for the compound response
        let sequence_resok = SEQUENCE4resok {
            sr_sessionid: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            sr_sequenceid: 234,
            sr_slotid: 567,
            sr_highest_slotid: 890,
            sr_target_highest_slotid: 890, // Assuming target is same as highest for simplicity
            sr_status_flags: 0,            // Assuming OK status
        };
        let sequence_op_res = nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(sequence_resok));

        // Create a GETXATTR4res for the compound response
        let getxattr_op_res =
            nfs_resop4::OP_GETXATTR(GETXATTR4res::NFS4_OK(xattrvalue4(Vec::<u8>::new())));

        // Create a SETXATTR4res for the compound response
        let setxattr_change_info = change_info4 {
            atomic: true,
            before: 123u64,
            after: 456u64,
        };
        let setxattr_op_res = nfs_resop4::OP_SETXATTR(SETXATTR4res::NFS4_OK(setxattr_change_info));

        // Create a LISTXATTRS4res for the compound response
        let listxattrs_res_ok = LISTXATTRS4resok {
            lxr_cookie: 123u64,
            lxr_names: vec![utf8string(b"test_name".to_vec())],
            lxr_eof: false,
        };
        let listxattrs_op_res =
            nfs_resop4::OP_LISTXATTRS(LISTXATTRS4res::NFS4_OK(listxattrs_res_ok));

        // Create a REMOVEXATTR4res for the compound response
        let removexattr_change_info = change_info4 {
            atomic: true,
            before: 456u64,
            after: 123u64,
        };
        let removexattr_op_res =
            nfs_resop4::OP_REMOVEXATTR(REMOVEXATTR4res::NFS4_OK(removexattr_change_info));

        // Create the compound response
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![
                sequence_op_res,
                getxattr_op_res,
                setxattr_op_res,
                listxattrs_op_res,
                removexattr_op_res,
            ],
        };

        // Pack the response to bytes
        let mut buffer = Vec::<u8>::new();
        compound_res
            .pack(&mut buffer)
            .expect("Failed to pack compound res");
        let buffer_bytes_mut = BytesMut::from(&buffer[..]);
        let buffer_clone = buffer_bytes_mut.clone();

        // Parse the compound response
        let result = NfsMessageParser::parse_compound::<COMPOUND4res>(buffer_bytes_mut);

        // Verify the result is RefNfsCompoundInfo
        assert!(
            result.is_ok(),
            "Failed to parse compound_res: {:?}",
            result.err()
        );

        let nfs_info = result.unwrap();
        assert_eq!(nfs_info.nfs_metadata.slot_id, 567);
        assert_eq!(nfs_info.nfs_metadata.sequence_id, 234);
        assert_eq!(nfs_info.op_vec.len(), 5);

        // check ops vec
        assert_eq!(nfs_info.op_vec[0], nfs_opnum4::OP_SEQUENCE);
        assert_eq!(nfs_info.op_vec[1], nfs_opnum4::OP_GETXATTR);
        assert_eq!(nfs_info.op_vec[2], nfs_opnum4::OP_SETXATTR);
        assert_eq!(nfs_info.op_vec[3], nfs_opnum4::OP_LISTXATTRS);
        assert_eq!(nfs_info.op_vec[4], nfs_opnum4::OP_REMOVEXATTR);

        // Verify the sessionid
        let expected_sessionid =
            sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        for i in 0..16 {
            assert_eq!(
                nfs_info.nfs_metadata.session_id.0[i],
                expected_sessionid.0[i]
            );
        }

        // verify buffer_ref
        assert_eq!(nfs_info.get_nfs_message(), buffer_clone.as_ref());
    }

    #[test]
    fn test_parsing_error() {
        let buffer = BytesMut::from(&[1; 100][..]);
        let result = NfsMessageParser::parse_compound::<COMPOUND4args>(buffer);
        println!("result: {:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_from_rpc_payload() {
        let payload = create_compound_args_raw_bytes();
        let result = NfsMessageParser::parse_from_rpc_payload(
            NfsCompoundType::Compound4args,
            BytesMut::from(payload),
        );
        assert!(result.is_ok());
        let nfs_info = result.unwrap();
        match nfs_info {
            RefNfsCompound::Compound4args(compound_info) => {
                assert_eq!(compound_info.op_vec.len(), 3);
            }
            _ => panic!("Expected Compound4args"),
        }
    }

    #[test]
    fn test_ref_nfs_compound_info_to_packable_nfs_compound_info() {
        let mut compound_args = create_test_compound_args_with_write_args_no_ref();
        let mut raw_bytes = Vec::new();
        compound_args
            .pack(&mut raw_bytes)
            .expect("Failed to pack compound_args");
        let ref_compound_info_result =
            NfsMessageParser::parse_compound::<COMPOUND4args>(BytesMut::from(&raw_bytes[..]));
        assert!(ref_compound_info_result.is_ok(), "Parsing failed");
        let ref_compound_info = ref_compound_info_result.unwrap();

        let packable_compound_info = ref_compound_info.into_packable_info();

        // check packable_compound_info's compound, should have correct owned write4args data
        let packable_compound_args = packable_compound_info.compound;
        assert_eq!(
            packable_compound_args.argarray.len(),
            compound_args.argarray.len()
        );

        let mut found_write_op = false;
        for op in &packable_compound_args.argarray {
            if let nfs_argop4::OP_WRITE(write_args) = op {
                assert!(matches!(write_args.data, DataPayload::Data(_)));
                let original_write_op_data = Bytes::from_static(b"Data within a compound request.");
                assert_eq!(write_args.data, DataPayload::Data(original_write_op_data));
                found_write_op = true;
                break;
            }
        }
        assert!(
            found_write_op,
            "WRITE operation not found in packable compound args"
        );
    }

    #[test]
    fn test_ref_nfs_compound_info_to_packable_nfs_compound_info_with_read_res() {
        let compound_res = create_test_compound_res_with_read_res_no_ref();
        let mut raw_bytes = Vec::new();
        compound_res
            .pack(&mut raw_bytes)
            .expect("Failed to pack compound_res");
        let ref_compound_info_result =
            NfsMessageParser::parse_compound::<COMPOUND4res>(BytesMut::from(&raw_bytes[..]));
        assert!(ref_compound_info_result.is_ok(), "Parsing failed");
        let ref_compound_info = ref_compound_info_result.unwrap();

        let packable_compound_info = ref_compound_info.into_packable_info();

        // check packable_compound_info's compound, should have correct owned read4res data
        let packable_compound_args = packable_compound_info.compound;
        assert_eq!(
            packable_compound_args.resarray.len(),
            compound_res.resarray.len()
        );

        let mut found_read_op = false;
        for op in &packable_compound_args.resarray {
            if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_res)) = op {
                assert!(matches!(read_res.data, DataPayload::Data(_)));
                let original_read_op_data = Bytes::from_static(b"Data within a compound request.");
                assert_eq!(read_res.data, DataPayload::Data(original_read_op_data));
                found_read_op = true;
                break;
            }
        }
        assert!(
            found_read_op,
            "READ operation not found in packable compound args"
        );
    }

    #[test]
    fn test_parse_packable_compound() {
        let compound_args = create_test_compound_args_with_write_args_no_ref();
        let mut raw_bytes = Vec::new();
        compound_args
            .pack(&mut raw_bytes)
            .expect("Failed to pack compound_args");
        let result = NfsMessageParser::parse_packable_compound::<COMPOUND4args>(BytesMut::from(
            &raw_bytes[..],
        ));
        assert!(result.is_ok(), "Parsing failed");
        let packable_info = result.unwrap();

        let packable_compound_args = packable_info.compound;
        assert_eq!(
            packable_compound_args.argarray.len(),
            compound_args.argarray.len()
        );

        let mut found_write_op = false;
        for op in packable_compound_args.argarray.into_iter() {
            if let nfs_argop4::OP_WRITE(write_args) = op {
                let original_write_op_data = Bytes::from_static(b"Data within a compound request.");
                assert!(
                    matches!(write_args.data, DataPayload::Data(data) if data == original_write_op_data)
                );
                found_write_op = true;
                break;
            }
        }
        assert!(
            found_write_op,
            "WRITE operation not found in packable compound args"
        );
    }
}
