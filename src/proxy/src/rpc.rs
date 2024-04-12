use std::io::Cursor;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::AsyncReadExt;

use crate::connections::ProxyStream;

// Each element is an RPC call.
pub struct RpcBatch {
    pub rpcs: Vec<Bytes>,
}

#[derive(Debug, PartialEq)]
pub enum RpcFragmentParseError {
    InvalidSizeTooSmall,
    SizeLimitExceeded,
    Incomplete,
}

pub const RPC_LAST_FRAG: u32 = 0x80000000;
pub const RPC_SIZE_MASK: u32 = 0x7FFFFFFF;
pub const RPC_HEADER_SIZE: usize = 4;

/* The sunrpc server implementation in linux has a maximum payload of 1MB + 1 page
 * (see include/linux/sunrpc/svc.h#RPCSVC_MAXPAYLOAD and sv_max_mesg).
 */
pub const RPC_MAX_SIZE: usize = 1024 * 1024 + 4 * 1024;
pub const RPC_MIN_SIZE: usize = 2;

impl RpcBatch {
    pub fn parse_batch(buffer: &mut BytesMut) -> Result<Option<RpcBatch>, RpcFragmentParseError> {
        let mut batch = RpcBatch { rpcs: Vec::new() };

        loop {
            match Self::check_rpc_message(Cursor::new(&buffer[..])) {
                Ok(len) => {
                    let rpc_message = buffer.split_to(len);
                    batch.rpcs.push(rpc_message.freeze());
                }
                Err(RpcFragmentParseError::Incomplete) => break,
                Err(e) => return Err(e),
            }
        }

        if batch.rpcs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(batch))
        }
    }

    pub fn check_rpc_message(mut src: Cursor<&[u8]>) -> Result<usize, RpcFragmentParseError> {
        loop {
            if src.remaining() < RPC_HEADER_SIZE {
                return Err(RpcFragmentParseError::Incomplete);
            }

            let fragment_header = src.get_u32();
            let fragment_size = (fragment_header & RPC_SIZE_MASK) as usize;
            let is_last_fragment = (fragment_header & RPC_LAST_FRAG) != 0;

            if fragment_size <= RPC_MIN_SIZE {
                return Err(RpcFragmentParseError::InvalidSizeTooSmall);
            }

            if fragment_size >= RPC_MAX_SIZE {
                return Err(RpcFragmentParseError::SizeLimitExceeded);
            }

            if src.remaining() < fragment_size {
                return Err(RpcFragmentParseError::Incomplete);
            }

            src.advance(fragment_size);

            if is_last_fragment {
                return Ok(src.position() as usize);
            }
        }
    }
}

pub async fn read_rpc_bytes(stream: &mut dyn ProxyStream) -> Result<Vec<u8>, tokio::io::Error> {
    let mut header = [0; RPC_HEADER_SIZE];
    stream.read_exact(&mut header).await?;

    // NOTE: onc-rpc crate does not support fragmentation out of the box. Add 4 to include the header.
    let len = (RPC_SIZE_MASK & extract_u32_from_bytes(&header)) + RPC_HEADER_SIZE as u32;

    let mut payload = vec![0; len as usize];
    payload[0..RPC_HEADER_SIZE].clone_from_slice(&header);

    stream.read_exact(&mut payload[RPC_HEADER_SIZE..]).await?;

    Ok(payload)
}

fn extract_u32_from_bytes(header: &[u8]) -> u32 {
    u32::from_be_bytes([header[0], header[1], header[2], header[3]])
}

#[cfg(test)]
pub mod test {
    use crate::rpc::RPC_MAX_SIZE;

    use super::{RpcBatch, RpcFragmentParseError, RPC_HEADER_SIZE, RPC_LAST_FRAG};
    use bytes::{BufMut, BytesMut};
    use rand::Rng;

    // Generates message fragments for tests
    //
    // This function generates a set of message fragments from random data. The fragments are constructed
    // in a way that they can be later assembled  into the full long message data
    // function.
    //
    // # Arguments
    // * `size` - The total size of the message.
    // * `num_fragments` - The number of fragments to generate.
    //
    pub fn generate_msg_fragments(size: usize, num_fragments: usize) -> (bytes::BytesMut, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();

        let fragment_data_size = data.len() / num_fragments;

        let mut data_buffer = bytes::BytesMut::new();
        for i in 0..num_fragments {
            let start_idx = i * fragment_data_size;
            let end_idx = std::cmp::min(size, start_idx + fragment_data_size);
            let fragment_data = &data[start_idx..end_idx];

            let mut header = (end_idx - start_idx) as u32;
            if end_idx == size {
                header |= 1 << 31;
            }

            data_buffer.extend_from_slice(&header.to_be_bytes());
            data_buffer.extend_from_slice(fragment_data);
        }
        assert_eq!(data_buffer.len(), (num_fragments * 4) + data.len());

        (data_buffer, data)
    }

    #[test]
    fn multiple_messages() {
        let mut b = BytesMut::with_capacity(8);
        b.put_u32(RPC_LAST_FRAG | 4);
        b.put_u32(42);
        b.put_u32(RPC_LAST_FRAG | 4);

        let batch = RpcBatch::parse_batch(&mut b);
        let batch = batch.unwrap().unwrap();
        assert_eq!(batch.rpcs[0].len(), 8);
        assert_eq!(batch.rpcs.len(), 1);

        b.put_u32(43);
        let batch = RpcBatch::parse_batch(&mut b);
        let batch = batch.unwrap().unwrap();
        assert_eq!(batch.rpcs[0].len(), 8);
        assert_eq!(batch.rpcs.len(), 1);

        let batch = RpcBatch::parse_batch(&mut b);
        assert!(matches!(batch, Ok(None)));
    }

    #[test]
    fn test_invalid_rpc_small_fragment() {
        let num_fragments = 1;
        let (mut input_buffer, _) = generate_msg_fragments(1, num_fragments);
        let result = RpcBatch::parse_batch(&mut input_buffer);
        assert!(matches!(
            result,
            Err(RpcFragmentParseError::InvalidSizeTooSmall)
        ));
    }

    #[test]
    fn test_invalid_rpc_big_fragment() {
        let num_fragments = 1;
        let (mut input_buffer, _) = generate_msg_fragments(RPC_MAX_SIZE + 1, num_fragments);
        let result = RpcBatch::parse_batch(&mut input_buffer);
        assert!(matches!(
            result,
            Err(RpcFragmentParseError::SizeLimitExceeded)
        ));
    }

    #[test]
    fn test_parse_batch_single_message() {
        // Create an input buffer with multiple RPC fragments
        let num_fragments = 3;
        let message_size = 12;
        let (mut input_buffer, _) = generate_msg_fragments(message_size, num_fragments);
        let mut rpc_batch = RpcBatch::parse_batch(&mut input_buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(1, rpc_batch.rpcs.len());
        let rpc_message = rpc_batch.rpcs.pop().expect("No RPC messages");

        let expected_message_size = num_fragments * RPC_HEADER_SIZE + message_size;
        assert_eq!(expected_message_size, rpc_message.len());
    }

    #[test]
    fn test_parse_batch_multiple_message() {
        // Create an input buffer with multiple RPC messages
        let num_fragments_1 = 3;
        let message_size_1 = 12;
        let (mut input_buffer, _) = generate_msg_fragments(message_size_1, num_fragments_1);

        let num_fragments_2 = 6;
        let message_size_2 = 24;
        let (input_buffer_2, _) = generate_msg_fragments(message_size_2, num_fragments_2);

        let num_fragments_3 = 1;
        let message_size_3 = 50;
        let (input_buffer_3, _) = generate_msg_fragments(message_size_3, num_fragments_3);

        input_buffer.extend_from_slice(&input_buffer_2);
        input_buffer.extend_from_slice(&input_buffer_3);

        let mut rpc_batch = RpcBatch::parse_batch(&mut input_buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(3, rpc_batch.rpcs.len());

        let rpc_message_3 = rpc_batch.rpcs.pop().expect("No RPC messages");
        let expected_message_size_3 = num_fragments_3 * RPC_HEADER_SIZE + message_size_3;
        assert_eq!(expected_message_size_3, rpc_message_3.len());

        let rpc_message_2 = rpc_batch.rpcs.pop().expect("No RPC messages");
        let expected_message_size_2 = num_fragments_2 * RPC_HEADER_SIZE + message_size_2;
        assert_eq!(expected_message_size_2, rpc_message_2.len());

        let rpc_message_1 = rpc_batch.rpcs.pop().expect("No RPC messages");
        let expected_message_size_1 = num_fragments_1 * RPC_HEADER_SIZE + message_size_1;
        assert_eq!(expected_message_size_1, rpc_message_1.len());
    }
}
