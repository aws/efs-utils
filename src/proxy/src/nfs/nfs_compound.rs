//! # NFS Compound Message Handling
//!
//! This module provides structures and traits for working with NFSv4.1 COMPOUND
//! requests and responses. It focuses on extracting essential metadata and the list
//! of operations contained within a single compound RPC call.
//!
//! ## `RefNfsCompoundInfo` vs. `PackableNfsCompoundInfo`
//!
//! Two primary structs are defined to handle NFS compound messages:
//!
//! - `RefNfsCompoundInfo`: This struct holds the parsed NFS compound message (`T`).
//!   If the Compound message includes a opaque data buffer, it will be stored as an OpaqueRaw reference.
//!   It is designed for efficiency when *reading* or *analyzing* incoming NFS requests/responses,
//!   as it avoids copying potentially large data buffers (like WRITE data). It's ideal
//!   when you only need temporary access tied to the lifetime of the original buffer.
//!
//! - `PackableNfsCompoundInfo`: This struct *owns* its data, including the NFS
//!   compound message (`T`) which typically contains owned data structures (e.g.,
//!   `Vec<u8>` for WRITE data instead of a reference). This makes it suitable for
//!   *constructing*, *modifying*, or *storing* NFS compound messages independently
//!   of any original buffer. It can be easily packed (serialized) for sending
//!   over the network.
//!

#![allow(unused)]

use crate::nfs::error::NfsError;
use crate::nfs::nfs4_1_xdr::*;
use crate::nfs::nfs4_1_xdr_ext::*;
use bytes::{Bytes, BytesMut};
use core::fmt::Debug;
use log::debug;
use onc_rpc::RpcMessage;
use std::io::Cursor;
use xdr_codec::{Pack, Unpack};

use super::nfs4_1_xdr::{
    nfs_cb_argop4, nfs_cb_opnum4, nfs_cb_resop4, CB_COMPOUND4args, CB_COMPOUND4res,
    CB_SEQUENCE4args,
};
use super::nfs4_1_xdr_ext::{opnum_from_cb_argop, opnum_from_cb_resop};

/// Extract metadata from argarray
fn extract_metadata_from_args(argarray: &[nfs_argop4]) -> NfsMetadata {
    if argarray.is_empty() {
        debug!("Failed to extract_metadata from COMPOUND4args: empty operation array");
        return NfsMetadata::default();
    }

    match argarray.first() {
        Some(nfs_argop4::OP_SEQUENCE(sequence_args)) => NfsMetadata {
            session_id: sequence_args.sa_sessionid,
            slot_id: sequence_args.sa_slotid,
            sequence_id: sequence_args.sa_sequenceid,
        },
        Some(nfs_argop4::OP_BIND_CONN_TO_SESSION(bind_args)) => NfsMetadata {
            session_id: bind_args.bctsa_sessid,
            slot_id: 0,
            sequence_id: 0,
        },
        Some(nfs_argop4::OP_DESTROY_SESSION(destroy_args)) => NfsMetadata {
            session_id: destroy_args.dsa_sessionid,
            slot_id: 0,
            sequence_id: 0,
        },
        Some(
            nfs_argop4::OP_EXCHANGE_ID(_)
            | nfs_argop4::OP_CREATE_SESSION(_)
            | nfs_argop4::OP_DESTROY_CLIENTID(_),
        ) => NfsMetadata::default(),
        _ => {
            debug!("Failed to extract_metadata from COMPOUND4args: first operation {:?} is not eligible for default metadata", argarray.first().map(|op| opnum_from_argop(op)));
            NfsMetadata::default()
        }
    }
}

/// Extract metadata from resarray
fn extract_metadata_from_res(resarray: &[nfs_resop4]) -> NfsMetadata {
    if resarray.is_empty() {
        debug!("Failed to extract_metadata from COMPOUND4res: empty operation array");
        return NfsMetadata::default();
    }

    match resarray.first() {
        Some(nfs_resop4::OP_SEQUENCE(SEQUENCE4res::NFS4_OK(sequence_res))) => NfsMetadata {
            session_id: sequence_res.sr_sessionid,
            slot_id: sequence_res.sr_slotid,
            sequence_id: sequence_res.sr_sequenceid,
        },
        Some(nfs_resop4::OP_BIND_CONN_TO_SESSION(BIND_CONN_TO_SESSION4res::NFS4_OK(bind_res))) => {
            NfsMetadata {
                session_id: bind_res.bctsr_sessid,
                slot_id: 0,
                sequence_id: 0,
            }
        }
        Some(nfs_resop4::OP_CREATE_SESSION(CREATE_SESSION4res::NFS4_OK(create_res))) => {
            NfsMetadata {
                session_id: create_res.csr_sessionid,
                slot_id: 0,
                sequence_id: 0,
            }
        }
        Some(
            nfs_resop4::OP_EXCHANGE_ID(_)
            | nfs_resop4::OP_DESTROY_SESSION(_)
            | nfs_resop4::OP_DESTROY_CLIENTID(_),
        ) => NfsMetadata::default(),
        _ => {
            debug!("Failed to extract_metadata from COMPOUND4res: first operation {:?} is not eligible for default metadata", resarray.first().map(|op| opnum_from_resop(op)));
            NfsMetadata::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NfsCompoundType {
    Compound4args,
    Compound4res,
    CbCompound4args,
    CbCompound4res,
}

#[derive(Clone, Debug)]
pub enum RefNfsCompound {
    Compound4args(RefNfsCompoundInfo<COMPOUND4args>),
    Compound4res(RefNfsCompoundInfo<COMPOUND4res>),
    CbCompound4args(RefNfsCompoundInfo<CB_COMPOUND4args>),
    CbCompound4res(RefNfsCompoundInfo<CB_COMPOUND4res>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NfsMetadata {
    pub session_id: sessionid4,
    pub slot_id: u32,
    pub sequence_id: u32,
}

impl Default for NfsMetadata {
    fn default() -> Self {
        Self {
            session_id: sessionid4([0; 16]),
            slot_id: 0,
            sequence_id: 0,
        }
    }
}

#[derive(Debug, Clone)]
// <'a>: Lifetime management, <T>: Either COMPOUND4args or COMPOUND4res
pub struct RefNfsCompoundInfo<T>
where
    T: NfsCompoundMessage,
{
    // NFS metadata - used for dispatching to the correct handler
    pub nfs_metadata: NfsMetadata,

    // Compound message
    pub compound: T,

    // Opcode vector
    pub op_vec: Vec<T::OpCodeType>,

    // A Owned buffer of the NFS compound message buffer, not increasing reference count
    nfs_body: BytesMut,
}

impl<T> RefNfsCompoundInfo<T>
where
    T: NfsCompoundMessage,
{
    pub fn new(
        nfs_metadata: NfsMetadata,
        compound: T,
        op_vec: Vec<T::OpCodeType>,
        nfs_body: BytesMut,
    ) -> Self {
        Self {
            nfs_metadata,
            compound,
            op_vec,
            nfs_body,
        }
    }

    pub fn into_bytes_mut(self) -> BytesMut {
        self.nfs_body
    }

    pub fn get_nfs_message(&self) -> &BytesMut {
        &self.nfs_body
    }

    pub fn into_packable_info(mut self) -> PackableNfsCompoundInfo<T> {
        PackableNfsCompoundInfo::from(self)
    }

    fn is_replacement_valid(original_op: &T::OpCodeType, new_op: &T::OpCodeType) -> bool {
        // Delegate to the compound message type's validation method
        T::is_op_replacement_valid(original_op, new_op)
    }

    // Replaces ALL existing operation's opcode in the nfs body bytes that matches the original op.
    // Input is the original op and the new op code.
    fn in_place_replace_all_target_operation_opcode_in_nfs_body(
        &mut self,
        original_op: &T::OpCodeType,
        new_op: &T::OpCodeType,
    ) -> Result<(), NfsError> {
        // We only allow certain operations to be replaced.
        if !Self::is_replacement_valid(&original_op, &new_op) {
            return Err(NfsError::InvalidOperationReplacement);
        }

        let mut offset_before_target_ops = 0;

        offset_before_target_ops += self
            .compound
            .get_offset_of_compound_message_before_first_op();

        // find all the ops need to be replaced in op_vec:
        let op_idx_needed_replacement: Vec<_> = self
            .op_vec
            .iter()
            .enumerate()
            .filter(|(_, op)| *op == original_op)
            .map(|(i, _)| i)
            .collect();
        // calculate the offset of each op need to be replaced:
        let count = op_idx_needed_replacement.len();

        if count == 0 {
            return Err(NfsError::ReplacementOperationNotFound);
        }

        // use a pre-allocated buffer to dummy pack the operation.
        let mut buf = Vec::<u8>::with_capacity(self.nfs_body.len());
        buf.resize(self.nfs_body.len(), 0);

        let mut offset_vec = vec![];
        offset_vec.push(offset_before_target_ops);
        // iterate until reach the farthest op index need to be replaced
        for op_idx in 0..op_idx_needed_replacement[count - 1] {
            // calculate the offset of the op before each target op.
            let offset = T::Op::get_op_serialized_size(
                &self.compound.get_ops_array_ref()[op_idx],
                &mut buf,
            )?;
            offset_before_target_ops += offset;
            offset_vec.push(offset_before_target_ops);
        }

        for op_idx in op_idx_needed_replacement {
            // Pack into exactly 4 bytes at the target offset
            let start_offset = offset_vec[op_idx];
            let end_offset = start_offset + OPS_CODE_SIZE;

            // Ensure we have enough space
            if end_offset <= self.nfs_body.len() {
                let mut slice: &mut [u8] = &mut self.nfs_body[start_offset..end_offset];
                match new_op.pack(&mut slice) {
                    Ok(_) => {}
                    Err(_) => return Err(NfsError::EncodeError),
                }
            } else {
                return Err(NfsError::EncodeError);
            }
        }
        Ok(())
    }

    // Generic method that requires TryFrom to be implemented
    pub fn replace_all_target_ops_with_new_ops<From, To>(&mut self) -> Result<(), NfsError>
    where
        T::Op: NfsOperationConversion<T::OpCodeType, From, To>,
    {
        let (original_op, new_op) = T::Op::get_op_code_type_for_conversion();
        self.in_place_replace_all_target_operation_opcode_in_nfs_body(&original_op, &new_op)?;

        let mut existing_ops_indices = Vec::new();
        for (i, op) in self.op_vec.iter_mut().enumerate() {
            if *op == original_op {
                existing_ops_indices.push(i);
                *op = new_op.clone();
            }
        }

        let ops_array = self.compound.get_ops_array_mut_ref();
        for op_idx in existing_ops_indices {
            let old_op = ops_array[op_idx].clone();

            // Extract the inner type from the enum
            if let Ok(new_op) = T::Op::convert(old_op) {
                ops_array[op_idx] = new_op;
            } else {
                return Err(NfsError::InvalidOperationReplacement);
            }
        }

        Ok(())
    }
}

impl<T> From<RefNfsCompoundInfo<T>> for PackableNfsCompoundInfo<T>
where
    T: NfsCompoundMessage,
{
    fn from(mut ref_info: RefNfsCompoundInfo<T>) -> Self {
        // Freeze the buffer to get a Bytes instance
        let frozen_body = ref_info.nfs_body.freeze();

        // Ensure the compound message owns all its internal data This will use frozen_body for
        // operations like WRITE4args that use OpaqueRaw to reference data within nfs_body
        ref_info.compound.make_internal_data_owned(&frozen_body);

        PackableNfsCompoundInfo {
            nfs_metadata: ref_info.nfs_metadata,
            compound: ref_info.compound,
            op_vec: ref_info.op_vec,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackableNfsCompoundInfo<CompoundType>
where
    CompoundType: NfsCompoundMessage,
{
    // NFS metadata
    pub nfs_metadata: NfsMetadata,

    // Owned compound message, which should contain opaque data buffer instead of a data_ref.
    pub compound: CompoundType,

    // Opcode vector
    pub op_vec: Vec<CompoundType::OpCodeType>,
    // No buffer_ref needed as this struct owns its data.
}

pub trait NfsCompoundMessage {
    // Type of operation to be inserted (e.g., nfs_argop4 or nfs_resop4)
    type Op: Clone
        + PartialEq
        + for<'a> Pack<&'a mut [u8]>
        + for<'a> Unpack<Cursor<&'a [u8]>>
        + GetOpSerializedSize;

    type OpCodeType: Debug + PartialEq + for<'a> Pack<&'a mut [u8]> + Clone;

    // Extracts metadata (session_id, slot_id, sequence_id) from self.
    fn extract_metadata(&self) -> NfsMetadata;

    // Retrieves opcode list from the compound message. Keep the original order.
    fn extract_opcode_vec(&self) -> Vec<Self::OpCodeType>;

    fn get_ops_array_ref(&self) -> &[Self::Op];

    // Returns a reference to the ops array.
    fn get_ops_array_mut_ref(&mut self) -> &mut [Self::Op];

    // Converts an operation to an opcode.
    fn op_to_opnum(&self, op: &Self::Op) -> Self::OpCodeType;

    /// Converts any internally borrowed data (e.g., in WRITE4args data or READ4res data) to an
    /// owned representation. This is typically used when transitioning from a zero-copy parsed
    /// structure to a structure that needs to live longer than the original input buffer.
    /// `nfs_body` is the raw buffer that `OpaqueRaw` might reference.
    fn make_internal_data_owned(&mut self, nfs_body: &Bytes) -> Result<(), NfsError>;

    // Returns the serialized size of the compound message before the first op.
    fn get_offset_of_compound_message_before_first_op(&self) -> usize;

    // Validates if one operation can be replaced with another
    fn is_op_replacement_valid(original_op: &Self::OpCodeType, new_op: &Self::OpCodeType) -> bool;
}

impl NfsCompoundMessage for COMPOUND4args {
    type Op = nfs_argop4;
    type OpCodeType = nfs_opnum4;

    fn extract_metadata(&self) -> NfsMetadata {
        extract_metadata_from_args(&self.argarray)
    }

    fn extract_opcode_vec(&self) -> Vec<Self::OpCodeType> {
        let mut op_vec = Vec::new();
        for op in self.argarray.iter() {
            op_vec.push(opnum_from_argop(op));
        }
        op_vec
    }

    fn get_ops_array_ref(&self) -> &[Self::Op] {
        &self.argarray
    }

    fn get_ops_array_mut_ref(&mut self) -> &mut [Self::Op] {
        &mut self.argarray
    }

    fn op_to_opnum(&self, op: &Self::Op) -> Self::OpCodeType {
        opnum_from_argop(op)
    }

    fn make_internal_data_owned(&mut self, nfs_body: &Bytes) -> Result<(), NfsError> {
        for arg_op in self.argarray.iter_mut() {
            if let nfs_argop4::OP_WRITE(write_args) = arg_op {
                if let DataPayload::DataRef(data_ref) = &write_args.data {
                    // Guard clause for out-of-bounds access with overflow protection
                    if data_ref
                        .offset
                        .checked_add(data_ref.len)
                        .map_or(true, |end| end > nfs_body.len())
                    {
                        return Err(NfsError::ParseError);
                    }

                    let end_offset = data_ref.offset + data_ref.len; // Safe after overflow check
                    let data_slice = nfs_body.slice(data_ref.offset..end_offset);

                    // Replace the DataRef with Data containing the slice
                    write_args.data = DataPayload::Data(data_slice);
                }
            }
        }
        Ok(())
    }

    fn get_offset_of_compound_message_before_first_op(&self) -> usize {
        // nfs body prefix for Compound4args:
        // length of 4 bytes tag length + tag + 4 bytes minorversion + 4 bytes ops array length
        let padded_tag_len = get_padded_size(self.tag.0.len());
        return size_of::<uint32_t>()
            + padded_tag_len
            + size_of::<uint32_t>()
            + size_of::<uint32_t>();
    }

    fn is_op_replacement_valid(original_op: &Self::OpCodeType, new_op: &Self::OpCodeType) -> bool {
        match (original_op, new_op) {
            (nfs_opnum4::OP_READ, nfs_opnum4::OP_AWSFILE_READ_BYPASS) => true,
            _ => false,
        }
    }
}

impl NfsCompoundMessage for COMPOUND4res {
    type Op = nfs_resop4;
    type OpCodeType = nfs_opnum4;

    fn extract_metadata(&self) -> NfsMetadata {
        extract_metadata_from_res(&self.resarray)
    }

    fn extract_opcode_vec(&self) -> Vec<Self::OpCodeType> {
        let mut op_vec = Vec::new();
        for op in self.resarray.iter() {
            op_vec.push(opnum_from_resop(op));
        }
        op_vec
    }

    fn get_ops_array_ref(&self) -> &[Self::Op] {
        &self.resarray
    }

    fn get_ops_array_mut_ref(&mut self) -> &mut [Self::Op] {
        &mut self.resarray
    }

    fn op_to_opnum(&self, op: &Self::Op) -> Self::OpCodeType {
        opnum_from_resop(op)
    }

    fn make_internal_data_owned(&mut self, nfs_body: &Bytes) -> Result<(), NfsError> {
        for res_op in self.resarray.iter_mut() {
            if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_res_ok)) = res_op {
                if let DataPayload::DataRef(data_ref) = &read_res_ok.data {
                    // Guard against out-of-bounds access with overflow protection
                    if data_ref
                        .offset
                        .checked_add(data_ref.len)
                        .map_or(true, |end| end > nfs_body.len())
                    {
                        return Err(NfsError::ParseError);
                    }

                    let end_offset = data_ref.offset + data_ref.len; // Safe after overflow check
                    let data_slice = nfs_body.slice(data_ref.offset..end_offset);

                    // Replace the DataRef with Data containing the slice
                    read_res_ok.data = DataPayload::Data(data_slice);
                }
            }
        }

        // At this point, all OP_READ operations have had their internal data made fully owned.
        Ok(())
    }

    fn get_offset_of_compound_message_before_first_op(&self) -> usize {
        // nfs body prefix for Compound4res:
        // 4 bytes length of status + 4 bytes tag length + tag + 4 bytes ops array length
        let padded_tag_len = get_padded_size(self.tag.0.len());
        return size_of::<uint32_t>()
            + size_of::<uint32_t>()
            + padded_tag_len
            + size_of::<uint32_t>();
    }

    fn is_op_replacement_valid(original_op: &Self::OpCodeType, new_op: &Self::OpCodeType) -> bool {
        matches!(
            (original_op, new_op),
            (nfs_opnum4::OP_AWSFILE_READ_BYPASS, nfs_opnum4::OP_READ)
        )
    }
}

impl NfsCompoundMessage for CB_COMPOUND4args {
    type Op = nfs_cb_argop4;
    type OpCodeType = nfs_cb_opnum4;

    fn extract_metadata(&self) -> NfsMetadata {
        // For now, we don't need metadata for CB_COMPOUND4args
        NfsMetadata::default()
    }

    fn extract_opcode_vec(&self) -> Vec<Self::OpCodeType> {
        let mut op_vec = Vec::new();
        for op in self.argarray.iter() {
            op_vec.push(self.op_to_opnum(op));
        }
        op_vec
    }

    fn get_ops_array_ref(&self) -> &[Self::Op] {
        &self.argarray
    }

    fn get_ops_array_mut_ref(&mut self) -> &mut [Self::Op] {
        &mut self.argarray
    }

    fn op_to_opnum(&self, op: &Self::Op) -> Self::OpCodeType {
        opnum_from_cb_argop(op)
    }

    fn make_internal_data_owned(&mut self, _nfs_body: &Bytes) -> Result<(), NfsError> {
        // Implement if CB_COMPOUND4args operations can contain
        // OpaqueRaw or OpaqueData fields that need owning.
        Ok(())
    }

    fn get_offset_of_compound_message_before_first_op(&self) -> usize {
        // nfs body prefix for CB_COMPOUND4args:
        // length of 4 bytes tag length + tag + 4 bytes minorversion + 4 bytes callback_ident + 4 bytes ops array length
        let padded_tag_len = get_padded_size(self.tag.0.len());
        return size_of::<uint32_t>()
            + padded_tag_len
            + size_of::<uint32_t>()
            + size_of::<uint32_t>()
            + size_of::<uint32_t>();
    }

    fn is_op_replacement_valid(original_op: &Self::OpCodeType, new_op: &Self::OpCodeType) -> bool {
        false
    }
}

impl NfsCompoundMessage for CB_COMPOUND4res {
    type Op = nfs_cb_resop4;
    type OpCodeType = nfs_cb_opnum4;

    fn extract_metadata(&self) -> NfsMetadata {
        // For now, we don't need metadata for CB_COMPOUND4res
        NfsMetadata::default()
    }

    fn extract_opcode_vec(&self) -> Vec<Self::OpCodeType> {
        let mut op_vec = Vec::new();
        for op in self.resarray.iter() {
            op_vec.push(self.op_to_opnum(op));
        }
        op_vec
    }

    fn get_ops_array_ref(&self) -> &[Self::Op] {
        &self.resarray
    }

    fn get_ops_array_mut_ref(&mut self) -> &mut [Self::Op] {
        &mut self.resarray
    }

    fn op_to_opnum(&self, op: &Self::Op) -> Self::OpCodeType {
        opnum_from_cb_resop(op)
    }

    fn make_internal_data_owned(&mut self, _nfs_body: &Bytes) -> Result<(), NfsError> {
        // Implement if CB_COMPOUND4res operations can contain
        // OpaqueRaw or OpaqueData fields that need owning.
        Ok(())
    }

    fn get_offset_of_compound_message_before_first_op(&self) -> usize {
        // nfs body prefix for CB_COMPOUND4res:
        // length of status + 4 bytes tag length + tag + 4 bytes ops array length
        let padded_tag_len = get_padded_size(self.tag.0.len());
        return size_of::<nfsstat4>()
            + size_of::<uint32_t>()
            + padded_tag_len
            + size_of::<uint32_t>();
    }

    fn is_op_replacement_valid(original_op: &Self::OpCodeType, new_op: &Self::OpCodeType) -> bool {
        false
    }
}

// Add this trait to handle enum variant extraction and conversion
pub trait NfsOperationConversion<OpCodeType, From, To> {
    fn get_op_code_type_for_conversion() -> (OpCodeType, OpCodeType);
    fn convert(op: Self) -> Result<Self, NfsError>
    where
        Self: Sized;
}

impl NfsOperationConversion<nfs_opnum4, AWSFILE_READ_BYPASS4res, READ4res> for nfs_resop4 {
    fn get_op_code_type_for_conversion() -> (nfs_opnum4, nfs_opnum4) {
        (nfs_opnum4::OP_AWSFILE_READ_BYPASS, nfs_opnum4::OP_READ)
    }

    fn convert(op: Self) -> Result<Self, NfsError> {
        match op {
            nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::NFS4_OK(inner)) => {
                Ok(nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
                    eof: inner.eof,
                    data: inner.data,
                })))
            }
            nfs_resop4::OP_AWSFILE_READ_BYPASS(AWSFILE_READ_BYPASS4res::default) => {
                Ok(nfs_resop4::OP_READ(READ4res::default))
            }
            _ => Err(NfsError::InvalidOperationReplacement),
        }
    }
}

impl NfsOperationConversion<nfs_opnum4, READ4args, AWSFILE_READ_BYPASS4args> for nfs_argop4 {
    fn get_op_code_type_for_conversion() -> (nfs_opnum4, nfs_opnum4) {
        (nfs_opnum4::OP_READ, nfs_opnum4::OP_AWSFILE_READ_BYPASS)
    }

    fn convert(op: Self) -> Result<Self, NfsError> {
        match op {
            // Since these 2 are same type through typedef, we can convert directly.
            nfs_argop4::OP_READ(read_args) => Ok(nfs_argop4::OP_AWSFILE_READ_BYPASS(read_args)),
            _ => Err(NfsError::InvalidOperationReplacement),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::prelude::v1::test;

    use super::*;
    use crate::nfs::nfs_parser::NfsMessageParser;
    use crate::nfs::{nfs4_1_xdr::*, nfs_test_utils::*};
    use bytes::BytesMut;

    #[test]
    fn test_default_nfs_metadata() {
        let metadata = NfsMetadata::default();
        assert_eq!(metadata.session_id, sessionid4([0; 16]));
        assert_eq!(metadata.slot_id, 0);
        assert_eq!(metadata.sequence_id, 0);
    }

    #[test]
    fn test_extract_metadata_create_session() {
        // Create a compound with CREATE_SESSION as the first operation
        let compound_args = COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 1,
            argarray: vec![create_test_create_session_arg()],
        };

        // Test that metadata extraction returns default values for CREATE_SESSION
        let metadata = compound_args.extract_metadata();
        assert_eq!(metadata.session_id, sessionid4([0; 16]));
        assert_eq!(metadata.slot_id, 0);
        assert_eq!(metadata.sequence_id, 0);
    }

    #[test]
    fn test_extract_metadata_create_session_response() {
        // Create a compound response with CREATE_SESSION as the first operation
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![create_test_create_session_res()],
        };

        // Test that metadata extraction returns the actual session ID for CREATE_SESSION response
        let metadata = compound_res.extract_metadata();
        // CREATE_SESSION response should contain the actual session ID
        assert_eq!(
            metadata.session_id,
            sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        );
        assert_eq!(metadata.slot_id, 0);
        assert_eq!(metadata.sequence_id, 0);
    }

    #[test]
    fn test_extract_metadata_eligible_first_ops_args() {
        // Test all eligible first operations for COMPOUND4args
        let test_cases = vec![
            (
                "BIND_CONN_TO_SESSION",
                create_test_bind_conn_to_session_arg(),
            ),
            ("EXCHANGE_ID", create_test_exchange_id_arg()),
            ("CREATE_SESSION", create_test_create_session_arg()),
            ("DESTROY_SESSION", create_test_destroy_session_arg()),
            ("DESTROY_CLIENTID", create_test_destroy_clientid_arg()),
        ];

        for (op_name, first_op) in test_cases {
            let compound_args = COMPOUND4args {
                tag: utf8string(vec![]),
                minorversion: 1,
                argarray: vec![first_op],
            };

            let metadata = compound_args.extract_metadata();
            // For operations that contain session IDs, verify the actual session ID is extracted
            match op_name {
                "BIND_CONN_TO_SESSION" => {
                    assert_eq!(
                        metadata.session_id,
                        sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                    );
                }
                "DESTROY_SESSION" => {
                    assert_eq!(
                        metadata.session_id,
                        sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                    );
                }
                _ => {
                    // For operations without session IDs, should return default
                    assert_eq!(metadata.session_id, sessionid4([0; 16]));
                }
            }
            assert_eq!(metadata.slot_id, 0);
            assert_eq!(metadata.sequence_id, 0);
        }
    }

    #[test]
    fn test_extract_metadata_eligible_first_ops_res() {
        // Test all eligible first operations for COMPOUND4res
        let test_cases = vec![
            (
                "BIND_CONN_TO_SESSION",
                create_test_bind_conn_to_session_res(),
            ),
            ("EXCHANGE_ID", create_test_exchange_id_res()),
            ("CREATE_SESSION", create_test_create_session_res()),
            ("DESTROY_SESSION", create_test_destroy_session_res()),
            ("DESTROY_CLIENTID", create_test_destroy_clientid_res()),
        ];

        for (op_name, first_op) in test_cases {
            let compound_res = COMPOUND4res {
                status: nfsstat4::NFS4_OK,
                tag: utf8string(vec![]),
                resarray: vec![first_op],
            };

            let metadata = compound_res.extract_metadata();
            // For operations that contain session IDs, verify the actual session ID is extracted
            match op_name {
                "BIND_CONN_TO_SESSION" => {
                    assert_eq!(
                        metadata.session_id,
                        sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                    );
                }
                "CREATE_SESSION" => {
                    assert_eq!(
                        metadata.session_id,
                        sessionid4([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                    );
                }
                _ => {
                    // For operations without session IDs, should return default
                    assert_eq!(metadata.session_id, sessionid4([0; 16]));
                }
            }
            assert_eq!(metadata.slot_id, 0);
            assert_eq!(metadata.sequence_id, 0);
        }
    }

    #[test]
    fn test_extract_metadata_ineligible_first_op() {
        // Test that non-eligible operations still fail
        let compound_args = COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 1,
            argarray: vec![get_sample_op_getattr_args()],
        };

        let metadata = compound_args.extract_metadata();
        // Should return default metadata for non-eligible operations
        assert_eq!(metadata, NfsMetadata::default());
    }

    #[test]
    fn test_make_internal_data_owned_compound4args_with_ref() {
        let expected_write_data_bytes = Bytes::from_static(b"Data within a compound request.");
        let (mut compound_args, raw_bytes) =
            create_test_compound_args_with_write_args_with_ref(&expected_write_data_bytes);

        // Find the OP_WRITE and its OpaqueRaw to prepare nfs_body_for_data_ref
        let mut opaque_raw = None;
        for arg in compound_args.argarray.iter() {
            if let nfs_argop4::OP_WRITE(write_args) = arg {
                if let DataPayload::DataRef(data_ref) = write_args.data {
                    opaque_raw = Some(data_ref);
                    break;
                }
            }
        }

        let opaque_raw = opaque_raw.expect("Test setup error: OP_WRITE with DataRef not found");

        assert_eq!(
            opaque_raw.len,
            expected_write_data_bytes.len(),
            "Test setup error: Mismatch in data_ref.len and expected data len."
        );

        let result = compound_args.make_internal_data_owned(&raw_bytes.freeze());
        assert!(result.is_ok());

        let write_op_arg = compound_args.argarray.iter().find_map(|op| {
            if let nfs_argop4::OP_WRITE(args) = op {
                Some(args)
            } else {
                None
            }
        });
        assert!(
            write_op_arg.is_some(),
            "OP_WRITE missing after make_internal_data_owned"
        );
        let write_args = write_op_arg.unwrap();
        assert!(
            matches!(write_args.data, DataPayload::Data(_)),
            "data should be Some after conversion"
        );
        assert_eq!(
            write_args.data,
            DataPayload::Data(expected_write_data_bytes),
            "Owned data does not match expected"
        );
    }

    #[test]
    fn test_make_internal_data_owned_compound4res_with_ref() {
        let expected_read_data_bytes = Bytes::from_static(b"Data within a compound request.");
        let (mut compound_res, raw_bytes) =
            create_test_compound_res_with_read_res_with_ref(&expected_read_data_bytes);

        // Find the OP_READ and its OpaqueRaw to prepare nfs_body_for_data_ref
        let mut found_opaque_raw: Option<OpaqueRaw> = None;
        for res in compound_res.resarray.iter() {
            if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_res)) = res {
                if let DataPayload::DataRef(data_ref) = read_res.data {
                    found_opaque_raw = Some(data_ref);
                    break;
                }
            }
        }
        let opaque_raw = found_opaque_raw
            .expect("Test setup error: OP_READ with data_ref not found in util-generated res.");

        assert_eq!(
            opaque_raw.len,
            expected_read_data_bytes.len(),
            "Test setup error: Mismatch in data_ref.len and expected data len."
        );

        let result = compound_res.make_internal_data_owned(&raw_bytes.freeze());
        assert!(result.is_ok());

        let read_op_res = compound_res.resarray.iter().find_map(|op| {
            if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_res)) = op {
                Some(read_res)
            } else {
                None
            }
        });
        assert!(
            read_op_res.is_some(),
            "OP_READ missing after make_internal_data_owned"
        );
        let read_res = read_op_res.unwrap();
        assert!(
            matches!(read_res.data, DataPayload::Data(_)),
            "data should be Some after conversion"
        );
        assert_eq!(
            read_res.data,
            DataPayload::Data(expected_read_data_bytes),
            "Owned data does not match expected"
        );
    }

    #[test]
    fn test_in_place_replace_operation_opcode_success() {
        // OP_SEQUENCE, OP_GETATTR, OP_READ_, OP_AWSFILE_READ_BYPASS, OP_AWSFILE_READ_BYPASS
        let mut compoundres_for_test: COMPOUND4res =
            get_sample_compound_res_with_multiple_read_bypass_res();
        let original_op = nfs_opnum4::OP_AWSFILE_READ_BYPASS;
        let new_op = nfs_opnum4::OP_READ;
        let payload_data = get_sample_op_read_res_with_data();

        // get payload from this nfs_resop4::OP_READ(READ4res::NFS4_OK(payload_data))
        let payload_data = match &compoundres_for_test.resarray[2] {
            nfs_resop4::OP_READ(READ4res::NFS4_OK((payload_data))) => payload_data.clone(),
            _ => panic!(
                "Expected OP_READ with NFS4_OK, got: {:?}",
                compoundres_for_test.resarray[2]
            ),
        };
        let payload_size = match &payload_data.data {
            DataPayload::Data(data) => data.len(),
            DataPayload::DataRef(data_ref) => data_ref.len,
        };

        let mut nfs_body = Vec::<u8>::new();
        compoundres_for_test
            .pack(&mut nfs_body)
            .expect("Failed to pack compoundres_for_test");

        let expected_nfs_body = nfs_body.clone();
        let mut ref_info =
            NfsMessageParser::parse_compound::<COMPOUND4res>(BytesMut::from(&nfs_body[..]))
                .expect("Failed to parse compoundres_for_test");

        ref_info
            .in_place_replace_all_target_operation_opcode_in_nfs_body(&original_op, &new_op)
            .expect("Failed to replace operation opcode");

        // Verify the result
        let modified_bytes = ref_info.into_bytes_mut();

        let modified_ref_info = NfsMessageParser::parse_compound::<COMPOUND4res>(modified_bytes)
            .expect("Failed to parse modified compoundres_for_test");

        // verify other unchanged ops:
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_GETATTR,
            nfs_opnum4::OP_READ, // was OP_AWSFILE_READ_BYPASS
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_READ, // was OP_AWSFILE_READ_BYPASS
            nfs_opnum4::OP_READ, // was OP_AWSFILE_READ_BYPASS
        ];

        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                modified_ref_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
        }

        let expect_res0 = nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
            eof: true,
            data: DataPayload::DataRef(OpaqueRaw {
                offset: 124,
                len: payload_size,
            }),
        }));

        let modified_res = &modified_ref_info.compound.resarray[2];
        assert_eq!(
            modified_res, &expect_res0,
            "Compound content changed after replace at index 2"
        );

        let expect_res1 = nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
            eof: true,
            data: DataPayload::DataRef(OpaqueRaw {
                offset: 180,
                len: payload_size,
            }),
        }));

        let modified_compound = modified_ref_info.compound.clone();
        let modified_res = &modified_compound.resarray[4];
        assert_eq!(
            modified_res, &expect_res1,
            "Compound content changed after replace at index 4"
        );

        // check the data payload is identical to original buffer: modified_res[offset:offset+len] == expected_nfs_body[offset:offset+len]
        let modified_data = modified_ref_info.into_bytes_mut();
        let modifired_payload_1 = modified_data[180..180 + payload_size].to_vec();
        let expected_payload_1 = expected_nfs_body[180..180 + payload_size].to_vec();
        assert_eq!(
            modifired_payload_1, expected_payload_1,
            "Data payload changed after replace"
        );

        // pick the second one:
        let expect_res2 = nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
            eof: true,
            data: DataPayload::DataRef(OpaqueRaw {
                offset: 228,
                len: payload_size,
            }),
        }));
        let modified_res2 = &modified_compound.resarray[5];
        assert_eq!(
            modified_res2, &expect_res2,
            "Compound content changed after replace at index 5"
        );

        // check the data payload is identical to original buffer: modified_res2[offset:offset+len] == expected_nfs_body[offset:offset+len]
        let modified_data2 = modified_data[228..228 + payload_size].to_vec();
        let expected_data2 = expected_nfs_body[228..228 + payload_size].to_vec();
        assert_eq!(
            modified_data2, expected_data2,
            "Data payload changed after replace"
        );
    }

    #[test]
    fn test_in_place_replace_operation_opcode_failure() {
        let compoundres_for_test = get_sample_compound_res();
        let mut nfs_body = Vec::<u8>::new();
        compoundres_for_test
            .pack(&mut nfs_body)
            .expect("Failed to pack compoundres_for_test");
        let mut ref_info =
            NfsMessageParser::parse_compound::<COMPOUND4res>(BytesMut::from(&nfs_body[..]))
                .expect("Failed to parse compoundres_for_test");

        // Test Case 1: Invalid replacement operation
        let original_op = nfs_opnum4::OP_LOOKUP;
        let new_op = nfs_opnum4::OP_LOOKUPP;

        let res = ref_info
            .in_place_replace_all_target_operation_opcode_in_nfs_body(&original_op, &new_op);
        assert!(
            res.is_err(),
            "Should fail with invalid replacement operation"
        );
        if let Err(e) = res {
            assert!(
                matches!(e, NfsError::InvalidOperationReplacement),
                "Expected InvalidOperationReplacement error, got: {:?}",
                e
            );
        }

        // Test Case 2: Operation not found
        let original_op = nfs_opnum4::OP_AWSFILE_READ_BYPASS;
        let new_op = nfs_opnum4::OP_READ;

        let mut nfs_body_2 = nfs_body.clone();
        compoundres_for_test
            .pack(&mut nfs_body_2)
            .expect("Failed to pack compoundres_for_test");
        let mut ref_info_2 =
            NfsMessageParser::parse_compound::<COMPOUND4res>(BytesMut::from(&nfs_body_2[..]))
                .expect("Failed to parse compoundres_for_test");
        let res = ref_info_2
            .in_place_replace_all_target_operation_opcode_in_nfs_body(&original_op, &new_op);
        assert!(res.is_err(), "Should fail with operation not found");
        if let Err(e) = res {
            assert!(
                matches!(e, NfsError::ReplacementOperationNotFound),
                "Expected ReplacementOperationNotFound error, got: {:?}",
                e
            );
        }
    }

    #[test]
    fn test_nfs_operation_conversion_invalid_replacement() {
        // Try to convert a nfs_resop4 variant that is not OP_AWSFILE_READ_BYPASS
        let op = get_sample_op_getattr_res();
        // We can only cast the conversion that implements NfsOperationConversion trait.
        // The convert can't be used to cast other operation.
        let result = <nfs_resop4 as NfsOperationConversion<
            nfs_opnum4,
            AWSFILE_READ_BYPASS4res,
            READ4res,
        >>::convert(op);
        assert!(
            result.is_err(),
            "Should fail with invalid operation replacement"
        );
        if let Err(e) = result {
            assert!(
                matches!(e, NfsError::InvalidOperationReplacement),
                "Expected InvalidOperationReplacement error, got: {:?}",
                e
            );
        }

        // Test if the read4res is not a NFS4_OK:
        let op = nfs_resop4::OP_READ(READ4res::default);
        let result: Result<nfs_resop4, NfsError> = <nfs_resop4 as NfsOperationConversion<
            nfs_opnum4,
            AWSFILE_READ_BYPASS4res,
            READ4res,
        >>::convert(op);
        assert!(
            result.is_err(),
            "Should fail with invalid operation replacement"
        );
        if let Err(e) = result {
            assert!(
                matches!(e, NfsError::InvalidOperationReplacement),
                "Expected InvalidOperationReplacement error, got: {:?}",
                e
            );
        }

        // NfsOperationConversion<nfs_opnum4, READ4args, AWSFILE_READ_BYPASS4args> is implemented
        // so we can convert READ4args to AWSFILE_READ_BYPASS4args
        let op = get_sample_op_read_args();
        let result: Result<nfs_argop4, NfsError> = <nfs_argop4 as NfsOperationConversion<
            nfs_opnum4,
            READ4args,
            AWSFILE_READ_BYPASS4args,
        >>::convert(op);
        assert!(
            result.is_ok(),
            "Should succeed with valid operation replacement"
        );
        assert!(
            matches!(result, Ok(nfs_argop4::OP_AWSFILE_READ_BYPASS(_))),
            "Expected OP_READ, got: {:?}",
            result
        );

        // NfsOperationConversion<nfs_opnum4, AWSFILE_READ_BYPASS4args, READ4args> is not implemented
        // but the complier will think AWSFILE_READ_BYPASS4args and READ4args are the same type as they are typedef-ed.
        // This is a valid conversion (still READ4args -> AWSFILE_READ_BYPASS4args), though not recommended, and we don't have a good way to forbid it...
        let op = get_sample_op_read_bypass_args(0, 0);
        let result: Result<nfs_argop4, NfsError> = <nfs_argop4 as NfsOperationConversion<
            nfs_opnum4,
            AWSFILE_READ_BYPASS4args,
            READ4args,
        >>::convert(op);
        assert!(
            result.is_err(),
            "Should fail with invalid operation replacement"
        );
        if let Err(e) = &result {
            assert!(
                matches!(e, NfsError::InvalidOperationReplacement),
                "Expected InvalidOperationReplacement error, got: {:?}",
                e
            );
        }
    }

    #[test]
    fn test_replace_all_read_args_with_read_bypass_args() {
        let mut compoundargs_for_test = get_sample_compound_args_with_multiple_read_args();
        let original_op = nfs_opnum4::OP_READ;
        let new_op = nfs_opnum4::OP_AWSFILE_READ_BYPASS;

        // pack the compoundargs_for_test
        let mut nfs_body = Vec::<u8>::new();
        compoundargs_for_test
            .pack(&mut nfs_body)
            .expect("Failed to pack compoundargs_for_test");

        // parse the compoundargs_for_test into RefNfsCompoundInfo
        let mut ref_info =
            NfsMessageParser::parse_compound::<COMPOUND4args>(BytesMut::from(&nfs_body[..]))
                .expect("Failed to parse compoundargs_for_test");

        // replace all the OP_READ with OP_AWSFILE_READ_BYPASS
        ref_info
            .replace_all_target_ops_with_new_ops::<READ4args, AWSFILE_READ_BYPASS4args>()
            .expect("Failed to replace all OP_READ with OP_AWSFILE_READ_BYPASS");

        // verify the result
        // verify the op_vec is correct
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_GETATTR,
            nfs_opnum4::OP_AWSFILE_READ_BYPASS,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_AWSFILE_READ_BYPASS,
            nfs_opnum4::OP_AWSFILE_READ_BYPASS,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                ref_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
        }

        // verify the compound is correct
        let expected_compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_op_getattr_args(),
                get_sample_op_read_bypass_args(123, 123),
                get_sample_put_fh_args(),
                get_sample_op_read_bypass_args(123, 123),
                get_sample_op_read_bypass_args(123, 123),
            ],
        };
        assert_eq!(
            ref_info.compound, expected_compound,
            "Compound content changed after replace"
        );
    }

    #[test]
    fn test_replace_all_read_bypass_res_with_read_res() {
        let mut compoundres_for_test = get_sample_compound_res_with_multiple_read_bypass_res();
        let original_op = nfs_opnum4::OP_AWSFILE_READ_BYPASS;
        let new_op = nfs_opnum4::OP_READ;

        // pack the compoundres_for_test
        let mut nfs_body = Vec::<u8>::new();
        compoundres_for_test
            .pack(&mut nfs_body)
            .expect("Failed to pack compoundres_for_test");

        // parse the compoundres_for_test into RefNfsCompoundInfo
        let mut ref_info =
            NfsMessageParser::parse_compound::<COMPOUND4res>(BytesMut::from(&nfs_body[..]))
                .expect("Failed to parse compoundres_for_test");

        // replace all the OP_READ with OP_AWSFILE_READ_BYPASS
        ref_info
            .replace_all_target_ops_with_new_ops::<AWSFILE_READ_BYPASS4res, READ4res>()
            .expect("Failed to replace all OP_AWSFILE_READ_BYPASS with OP_READ");

        // verify the result
        // verify the op_vec is correct
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_GETATTR,
            nfs_opnum4::OP_READ,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_READ,
            nfs_opnum4::OP_READ,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                ref_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
        }

        // compound verification is alread done in test_in_place_replace_operation_opcode_success
    }
}
