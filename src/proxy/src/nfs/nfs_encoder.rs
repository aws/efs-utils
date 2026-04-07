#![allow(unused)]

use crate::nfs::error::NfsError;
use crate::nfs::nfs_compound::{NfsCompoundMessage, PackableNfsCompoundInfo};
use xdr_codec::Pack;

#[allow(dead_code)]
pub struct NfsMessageEncoder;

#[allow(dead_code)]
impl NfsMessageEncoder {
    pub fn encode_compound<T: NfsCompoundMessage + Pack<Vec<u8>>>(
        compound_info: PackableNfsCompoundInfo<T>,
    ) -> Result<Vec<u8>, NfsError> {
        let mut buffer = Vec::new();
        compound_info
            .compound
            .pack(&mut buffer)
            .map_err(|_| NfsError::EncodeError)?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::nfs::{
        nfs4_1_xdr::{nfs_opnum4, sessionid4},
        nfs_compound::NfsMetadata,
        nfs_test_utils::{
            create_test_compound_args_with_write_args_no_ref,
            create_test_compound_args_with_write_args_with_ref,
        },
    };

    #[test]
    fn test_encode_compound_args() {
        let compound_args = create_test_compound_args_with_write_args_no_ref();
        let mut raw_bytes = Vec::new();
        compound_args
            .pack(&mut raw_bytes)
            .expect("Failed to pack compound");

        let compound_info = PackableNfsCompoundInfo {
            compound: compound_args,
            nfs_metadata: NfsMetadata {
                session_id: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                slot_id: 456,
                sequence_id: 123,
            },
            op_vec: vec![nfs_opnum4::OP_SEQUENCE, nfs_opnum4::OP_GETATTR],
        };

        let encode_result = NfsMessageEncoder::encode_compound(compound_info);
        assert!(
            encode_result.is_ok(),
            "Encoding compound args should succeed"
        );
        let encoded = encode_result.unwrap();
        assert_eq!(encoded.len(), raw_bytes.len());
        assert_eq!(encoded, raw_bytes);
    }

    #[test]
    fn test_encode_compound_with_ref_expect_failure() {
        let (compound_args, _) =
            create_test_compound_args_with_write_args_with_ref(&Bytes::from_static(b""));
        let mut raw_bytes = Vec::new();
        let result = compound_args.pack(&mut raw_bytes);
        assert!(
            result.is_err(),
            "Packing compound args with reference should fail"
        );

        let compound_info = PackableNfsCompoundInfo {
            compound: compound_args,
            nfs_metadata: NfsMetadata {
                session_id: sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                slot_id: 456,
                sequence_id: 123,
            },
            op_vec: vec![
                nfs_opnum4::OP_SEQUENCE,
                nfs_opnum4::OP_GETATTR,
                nfs_opnum4::OP_WRITE,
            ],
        };

        let encoded = NfsMessageEncoder::encode_compound(compound_info);
        assert!(
            encoded.is_err(),
            "Encoding compound with reference should fail"
        );
        // assert error type
        assert_eq!(encoded.err().unwrap(), NfsError::EncodeError);
    }
}
