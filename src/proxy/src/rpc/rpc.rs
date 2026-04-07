use std::{
    io::Cursor,
    sync::{atomic::AtomicU64, Arc},
};

use crate::connections::ProxyStream;
use bytes::{Buf, BytesMut};
use tokio::io::AsyncReadExt;

use super::rpc_error::RpcFragmentParseError;

pub const RPC_LAST_FRAG: u32 = 0x80000000;
pub const RPC_SIZE_MASK: u32 = 0x7FFFFFFF;
pub const RPC_HEADER_SIZE: usize = 4;

/* The sunrpc server implementation in linux has a maximum payload of 1MB + 1 page
 * (see include/linux/sunrpc/svc.h#RPCSVC_MAXPAYLOAD and sv_max_mesg).
 */
pub const RPC_MAX_SIZE: usize = 1024 * 1024 + 4 * 1024;
pub const RPC_MIN_SIZE: usize = 2;

pub const LAST_RECORD_FRAGMENT_FLAG: u32 = 0x8000_0000;
pub const NFS_PROGRAM: u32 = 100003;
// TOOD: just a placeholder for now (use nfs4_1.x::NFS_BACKCHANNEL_PROGRAM), change when we have a real backchannel program
pub const NFS_BACKCHANNEL_PROGRAM: u32 = 0x4000_0000;

pub const READER_BUFFER_SIZE: usize = RPC_MAX_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum RpcBufferedReaderError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("RPC message too large")]
    SizeLimitExceeded,
    #[error("RPC message too small")]
    InvalidSizeTooSmall,
    #[error("Shutdown")]
    EndOfFile,
}

pub struct BufferedRpcReader<R> {
    read_half: R,
    read_count: Option<Arc<AtomicU64>>,
    buffer: BytesMut,
}

impl<R> BufferedRpcReader<R>
where
    R: AsyncReadExt + Unpin,
{
    pub fn new(read_half: R, read_count: Option<Arc<AtomicU64>>) -> Self {
        Self {
            read_half,
            read_count,
            buffer: BytesMut::with_capacity(READER_BUFFER_SIZE),
        }
    }

    pub async fn read(&mut self) -> Result<RpcBatch, RpcBufferedReaderError> {
        loop {
            // Read data into buffer
            match self.read_half.read_buf(&mut self.buffer).await {
                Ok(0) => return Err(RpcBufferedReaderError::EndOfFile),
                Ok(n) => {
                    // Successfully read data
                    if let Some(count) = &self.read_count {
                        count.fetch_add(n as u64, std::sync::atomic::Ordering::AcqRel);
                    }
                }
                Err(e) => return Err(RpcBufferedReaderError::IoError(e)),
            }

            // Try to parse a batch from the current buffer
            match RpcBatch::parse_batch(&mut self.buffer) {
                Ok(Some(batch)) => return Ok(batch),
                Err(RpcFragmentParseError::InvalidSizeTooSmall) => {
                    return Err(RpcBufferedReaderError::InvalidSizeTooSmall);
                }
                Err(RpcFragmentParseError::SizeLimitExceeded) => {
                    return Err(RpcBufferedReaderError::SizeLimitExceeded);
                }
                Ok(None) | Err(RpcFragmentParseError::Incomplete) => {
                    // Need more data, continue to read
                }
            }

            // Ensure buffer has capacity
            if self.buffer.capacity() == 0 {
                self.buffer.reserve(READER_BUFFER_SIZE);
            }
        }
    }
}

// Each element is a complete RPC message.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcBatch {
    pub rpcs: Vec<BytesMut>,
}

impl RpcBatch {
    pub fn parse_batch(buffer: &mut BytesMut) -> Result<Option<RpcBatch>, RpcFragmentParseError> {
        let mut batch = RpcBatch { rpcs: Vec::new() };

        loop {
            match check_rpc_message(Cursor::new(&buffer[..])) {
                Ok((len, fragment_count)) => {
                    if fragment_count == 1 {
                        let rpc_message = buffer.split_to(len);
                        batch.rpcs.push(rpc_message);
                    } else {
                        let reconstructed =
                            Self::reconstruct_fragments(buffer, len, fragment_count);
                        batch.rpcs.push(reconstructed);
                    }
                }
                Err(RpcFragmentParseError::Incomplete) => {
                    break;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        if batch.rpcs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(batch))
        }
    }

    fn reconstruct_fragments(
        buffer: &mut BytesMut,
        total_len: usize,
        fragment_count: usize,
    ) -> BytesMut {
        let fragment_data = buffer.split_to(total_len);
        let mut cursor = Cursor::new(&fragment_data[..]);

        // Calculate total payload size (total - all headers)
        let total_payload_size = total_len - (fragment_count * RPC_HEADER_SIZE);

        // Allocate buffer and prepare reconstructed header
        let mut reconstructed = BytesMut::with_capacity(RPC_HEADER_SIZE + total_payload_size);
        let reconstructed_header = (total_payload_size as u32) | RPC_LAST_FRAG;
        reconstructed.extend_from_slice(&reconstructed_header.to_be_bytes());

        // Process each fragment and append payload directly to buffer
        for _ in 0..fragment_count {
            let fragment_header = cursor.get_u32();
            let fragment_size = (fragment_header & RPC_SIZE_MASK) as usize;

            // Extract payload slice and append to reconstructed message
            let payload_start = cursor.position() as usize;
            let payload_end = payload_start + fragment_size;
            let payload_slice = &fragment_data[payload_start..payload_end];
            reconstructed.extend_from_slice(payload_slice);

            // Advance cursor past this fragment's payload
            cursor.advance(fragment_size);
        }

        // Return reconstructed single-fragment RPC message
        reconstructed
    }
}

pub fn check_rpc_message(mut src: Cursor<&[u8]>) -> Result<(usize, usize), RpcFragmentParseError> {
    let mut fragment_count = 0;
    loop {
        if src.remaining() < RPC_HEADER_SIZE {
            return Err(RpcFragmentParseError::Incomplete);
        }

        let fragment_header = src.get_u32();
        let fragment_size = (fragment_header & RPC_SIZE_MASK) as usize;
        let is_last_fragment = (fragment_header & RPC_LAST_FRAG) != 0;

        if fragment_size < RPC_MIN_SIZE {
            return Err(RpcFragmentParseError::InvalidSizeTooSmall);
        }

        if fragment_size > RPC_MAX_SIZE {
            return Err(RpcFragmentParseError::SizeLimitExceeded);
        }

        if src.remaining() < fragment_size {
            return Err(RpcFragmentParseError::Incomplete);
        }

        src.advance(fragment_size);
        fragment_count += 1;

        if is_last_fragment {
            return Ok((src.position() as usize, fragment_count));
        }
    }
}

pub async fn read_rpc_bytes(stream: &mut dyn ProxyStream) -> Result<Vec<u8>, tokio::io::Error> {
    let mut header = [0; RPC_HEADER_SIZE];
    stream.read_exact(&mut header).await?;

    // NOTE: onc-rpc crate does not support fragmentation out of the box. Add 4 to include the header.
    let fragment_size = RPC_SIZE_MASK & extract_u32_from_bytes(&header);
    let len = fragment_size
        .checked_add(RPC_HEADER_SIZE as u32)
        .ok_or_else(|| {
            tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "RPC message size overflow",
            )
        })?;

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
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        task::{Context, Poll},
    };

    use crate::{
        rpc::rpc::{
            BufferedRpcReader, RpcBatch, RpcBufferedReaderError, RPC_MAX_SIZE, RPC_MIN_SIZE,
        },
        test_utils::generate_rpc_msg_fragments,
    };
    use tokio::io::AsyncRead;

    use super::{RpcFragmentParseError, RPC_HEADER_SIZE, RPC_LAST_FRAG, RPC_SIZE_MASK};
    use bytes::{BufMut, BytesMut};

    // Mock reader that returns predefined data
    struct MockReader {
        chunks: Vec<Vec<u8>>,
        current_chunk: usize,
        position_in_chunk: usize,
    }

    impl MockReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks,
                current_chunk: 0,
                position_in_chunk: 0,
            }
        }
    }

    impl AsyncRead for MockReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();

            if this.current_chunk >= this.chunks.len() {
                return Poll::Ready(Ok(())); // EOF
            }

            let chunk = &this.chunks[this.current_chunk];
            let remaining = chunk.len() - this.position_in_chunk;
            let to_copy = std::cmp::min(remaining, buf.remaining());

            if to_copy > 0 {
                buf.put_slice(&chunk[this.position_in_chunk..this.position_in_chunk + to_copy]);
                this.position_in_chunk += to_copy;
            }

            if this.position_in_chunk >= chunk.len() {
                this.current_chunk += 1;
                this.position_in_chunk = 0;
            }

            Poll::Ready(Ok(()))
        }
    }

    // Helper function to create a valid RPC message
    fn create_rpc_message(payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        let size = payload.len() as u32;
        message.extend_from_slice(&(RPC_LAST_FRAG | size).to_be_bytes());
        message.extend_from_slice(payload);
        message
    }

    #[tokio::test]
    async fn test_buffered_rpc_reader_read_single_message() {
        // Create a mock reader with a single RPC message
        let payload = vec![1, 2, 3, 4];
        let message = create_rpc_message(&payload);
        let reader = MockReader::new(vec![message]);

        let read_count = Arc::new(AtomicU64::new(0));
        let mut buffered_reader = BufferedRpcReader::new(reader, Some(read_count.clone()));

        // Read the message
        let batch = buffered_reader.read().await.unwrap();

        // Verify the batch contains the expected message
        assert_eq!(batch.rpcs.len(), 1);
        assert_eq!(batch.rpcs[0].len(), payload.len() + RPC_HEADER_SIZE);

        // Verify read count was updated
        assert_eq!(
            read_count.load(Ordering::Relaxed),
            (payload.len() + RPC_HEADER_SIZE) as u64
        );
    }

    #[tokio::test]
    async fn test_buffered_rpc_reader_read_multiple_messages() {
        // Create a mock reader with multiple RPC messages
        let payload1 = vec![1, 2, 3, 4];
        let payload2 = vec![5, 6, 7, 8];
        let message1 = create_rpc_message(&payload1);
        let message2 = create_rpc_message(&payload2);

        let combined = [message1.clone(), message2.clone()].concat();
        let reader = MockReader::new(vec![combined]);

        let mut buffered_reader = BufferedRpcReader::new(reader, None);

        // Read the batch
        let batch = buffered_reader.read().await.unwrap();

        // Verify the batch contains both messages
        assert_eq!(batch.rpcs.len(), 2);
        assert_eq!(batch.rpcs[0].len(), payload1.len() + RPC_HEADER_SIZE);
        assert_eq!(batch.rpcs[1].len(), payload2.len() + RPC_HEADER_SIZE);
    }

    #[tokio::test]
    async fn test_buffered_rpc_reader_read_fragmented_message() {
        // Create a mock reader with a message split across multiple reads
        let payload = vec![1, 2, 3, 4];
        let message = create_rpc_message(&payload);

        // Split the message into two chunks
        let chunk1 = message[0..2].to_vec();
        let chunk2 = message[2..].to_vec();
        let reader = MockReader::new(vec![chunk1, chunk2]);

        let mut buffered_reader = BufferedRpcReader::new(reader, None);

        // Read the message
        let batch = buffered_reader.read().await.unwrap();

        // Verify the batch contains the expected message
        assert_eq!(batch.rpcs.len(), 1);
        assert_eq!(batch.rpcs[0].len(), payload.len() + RPC_HEADER_SIZE);
    }

    #[tokio::test]
    async fn test_buffered_rpc_reader_read_too_large_message() {
        // Create a mock reader with a message that claims to be too large
        let mut message = Vec::new();
        message.extend_from_slice(&(RPC_LAST_FRAG | (RPC_MAX_SIZE as u32 + 1)).to_be_bytes());
        // We don't need to add the actual payload since the check happens before reading it

        let reader = MockReader::new(vec![message]);
        let mut buffered_reader = BufferedRpcReader::new(reader, None);

        // Read should return SizeLimitExceeded error
        let result = buffered_reader.read().await;
        assert!(matches!(
            result,
            Err(RpcBufferedReaderError::SizeLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn test_buffered_rpc_reader_read_empty_stream() {
        // Create a mock reader that returns EOF immediately
        let reader = MockReader::new(vec![]);
        let mut buffered_reader = BufferedRpcReader::new(reader, None);

        // Read should return EndOfFile error
        let result = buffered_reader.read().await;
        assert!(matches!(result, Err(RpcBufferedReaderError::EndOfFile)));
    }

    #[tokio::test]
    async fn test_buffered_rpc_reader_read_invalid_message() {
        // Create a mock reader with an invalid message (too small)
        let mut message = Vec::new();
        message.extend_from_slice(&(RPC_LAST_FRAG | 1).to_be_bytes()); // Size 1 is too small
        message.push(0); // 1 byte payload

        let reader = MockReader::new(vec![message]);
        let mut buffered_reader = BufferedRpcReader::new(reader, None);

        // Read should return InvalidSizeTooSmall error
        let result = buffered_reader.read().await;
        assert!(matches!(
            result,
            Err(RpcBufferedReaderError::InvalidSizeTooSmall)
        ));
    }

    #[test]
    fn test_parse_batch_multiple_messages() {
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
    fn test_parse_batch_invalid_rpc_small_fragment() {
        let num_fragments = 1;
        let (mut input_buffer, _) = generate_rpc_msg_fragments(RPC_MIN_SIZE - 1, num_fragments);
        let result = RpcBatch::parse_batch(&mut input_buffer);
        assert!(matches!(
            result,
            Err(RpcFragmentParseError::InvalidSizeTooSmall)
        ));
    }

    #[test]
    fn test_parse_batch_invalid_rpc_big_fragment() {
        let num_fragments = 1;
        let (mut input_buffer, _) = generate_rpc_msg_fragments(RPC_MAX_SIZE + 1, num_fragments);
        let result = RpcBatch::parse_batch(&mut input_buffer);
        assert!(matches!(
            result,
            Err(RpcFragmentParseError::SizeLimitExceeded)
        ));
    }

    #[test]
    fn test_parse_batch_single_fragment_message() {
        // Create an input buffer with a single fragment message
        let num_fragments = 1;
        let message_size = 12;
        let (mut input_buffer, _) = generate_rpc_msg_fragments(message_size, num_fragments);
        let mut rpc_batch = RpcBatch::parse_batch(&mut input_buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(1, rpc_batch.rpcs.len());
        let rpc_message = rpc_batch.rpcs.pop().expect("No RPC messages");

        // Single fragment should preserve original structure
        let expected_message_size = num_fragments * RPC_HEADER_SIZE + message_size;
        assert_eq!(expected_message_size, rpc_message.len());
    }

    #[test]
    fn test_parse_batch_multi_fragment_message() {
        let num_fragments = 3;
        let message_size = 12;
        let (mut input_buffer, original_data) =
            generate_rpc_msg_fragments(message_size, num_fragments);
        let mut rpc_batch = RpcBatch::parse_batch(&mut input_buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(1, rpc_batch.rpcs.len());
        let rpc_message = rpc_batch.rpcs.pop().expect("No RPC messages");

        // Reconstructed message should have single header + payload
        let expected_message_size = RPC_HEADER_SIZE + message_size;
        assert_eq!(expected_message_size, rpc_message.len());

        // Verify the header indicates it's the last (and only) fragment
        let header_bytes = &rpc_message[0..4];
        let header = u32::from_be_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        assert_eq!(header & RPC_LAST_FRAG, RPC_LAST_FRAG);
        assert_eq!(header & RPC_SIZE_MASK, message_size as u32);

        let payload = &rpc_message[RPC_HEADER_SIZE..];
        assert_eq!(payload, &original_data[..]);
    }

    #[test]
    fn test_reconstruct_fragments_complete() {
        let num_fragments = 5;
        let message_size = 100;
        let (mut input_buffer, original_data) =
            generate_rpc_msg_fragments(message_size, num_fragments);

        let batch = RpcBatch::parse_batch(&mut input_buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(batch.rpcs.len(), 1);
        let reconstructed = &batch.rpcs[0];

        assert_eq!(reconstructed.len(), RPC_HEADER_SIZE + message_size);

        let payload = &reconstructed[RPC_HEADER_SIZE..];
        assert_eq!(payload, &original_data[..]);

        // Buffer should have been consumed
        assert!(input_buffer.is_empty());
    }

    #[test]
    fn test_fragment_reconstruction_edge_cases() {
        // Test with minimum size fragments
        let (mut input_buffer, original_data) = generate_rpc_msg_fragments(RPC_MIN_SIZE * 2, 2);
        let batch = RpcBatch::parse_batch(&mut input_buffer).unwrap().unwrap();

        assert_eq!(batch.rpcs.len(), 1);
        let reconstructed = &batch.rpcs[0];
        assert_eq!(reconstructed.len(), RPC_HEADER_SIZE + (RPC_MIN_SIZE * 2));
        assert_eq!(&reconstructed[RPC_HEADER_SIZE..], &original_data[..]);
    }

    #[test]
    fn test_parse_batch_multiple_message() {
        // Create an input buffer with multiple RPC messages of different fragment counts
        let num_fragments_1 = 3;
        let message_size_1 = 12;
        let (mut input_buffer, _) = generate_rpc_msg_fragments(message_size_1, num_fragments_1);

        let num_fragments_2 = 6;
        let message_size_2 = 24;
        let (input_buffer_2, _) = generate_rpc_msg_fragments(message_size_2, num_fragments_2);

        let num_fragments_3 = 1;
        let message_size_3 = 50;
        let (input_buffer_3, _) = generate_rpc_msg_fragments(message_size_3, num_fragments_3);

        input_buffer.extend_from_slice(&input_buffer_2);
        input_buffer.extend_from_slice(&input_buffer_3);

        let mut rpc_batch = RpcBatch::parse_batch(&mut input_buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(3, rpc_batch.rpcs.len());

        // Message 3 (single fragment) - preserved original structure
        let rpc_message_3 = rpc_batch.rpcs.pop().expect("No RPC messages");
        let expected_message_size_3 = RPC_HEADER_SIZE + message_size_3;
        assert_eq!(expected_message_size_3, rpc_message_3.len());

        // Message 2 (multi-fragment) - reconstructed with single header
        let rpc_message_2 = rpc_batch.rpcs.pop().expect("No RPC messages");
        let expected_message_size_2 = RPC_HEADER_SIZE + message_size_2;
        assert_eq!(expected_message_size_2, rpc_message_2.len());

        // Message 1 (multi-fragment) - reconstructed with single header
        let rpc_message_1 = rpc_batch.rpcs.pop().expect("No RPC messages");
        let expected_message_size_1 = RPC_HEADER_SIZE + message_size_1;
        assert_eq!(expected_message_size_1, rpc_message_1.len());
    }

    #[test]
    fn test_check_rpc_message_valid_cases() {
        // Test single fragment
        let message_size = 20;
        let (buffer, _) = generate_rpc_msg_fragments(message_size, 1);
        let cursor = std::io::Cursor::new(&buffer[..]);
        let result = super::check_rpc_message(cursor).unwrap();
        assert_eq!(result, (RPC_HEADER_SIZE + message_size, 1));

        // Test multiple fragments
        let message_size = 30;
        let num_fragments = 4;
        let (buffer, _) = generate_rpc_msg_fragments(message_size, num_fragments);
        let cursor = std::io::Cursor::new(&buffer[..]);
        let result = super::check_rpc_message(cursor).unwrap();
        assert_eq!(
            result,
            (
                (RPC_HEADER_SIZE * num_fragments) + message_size,
                num_fragments
            )
        );

        // Test mixed fragment sizes
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&8u32.to_be_bytes());
        buffer.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        buffer.extend_from_slice(&12u32.to_be_bytes());
        buffer.extend_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        buffer.extend_from_slice(&(RPC_LAST_FRAG | 6u32).to_be_bytes());
        buffer.extend_from_slice(&[21, 22, 23, 24, 25, 26]);

        let cursor = std::io::Cursor::new(&buffer[..]);
        let result = super::check_rpc_message(cursor).unwrap();
        assert_eq!(result, ((3 * RPC_HEADER_SIZE) + 8 + 12 + 6, 3));
    }

    #[test]
    fn test_check_rpc_message_error_cases() {
        // Test incomplete header
        let buffer = vec![0x80, 0x00, 0x00];
        let cursor = std::io::Cursor::new(&buffer[..]);
        assert!(matches!(
            super::check_rpc_message(cursor),
            Err(RpcFragmentParseError::Incomplete)
        ));

        // Test incomplete payload
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(RPC_LAST_FRAG | 10u32).to_be_bytes());
        buffer.extend_from_slice(&[1, 2, 3, 4, 5]);
        let cursor = std::io::Cursor::new(&buffer[..]);
        assert!(matches!(
            super::check_rpc_message(cursor),
            Err(RpcFragmentParseError::Incomplete)
        ));

        // Test size too small
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(RPC_LAST_FRAG | (RPC_MIN_SIZE as u32 - 1)).to_be_bytes());
        buffer.push(0);
        let cursor = std::io::Cursor::new(&buffer[..]);
        assert!(matches!(
            super::check_rpc_message(cursor),
            Err(RpcFragmentParseError::InvalidSizeTooSmall)
        ));

        // Test size too large
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(RPC_LAST_FRAG | (RPC_MAX_SIZE as u32 + 1)).to_be_bytes());
        let cursor = std::io::Cursor::new(&buffer[..]);
        assert!(matches!(
            super::check_rpc_message(cursor),
            Err(RpcFragmentParseError::SizeLimitExceeded)
        ));
    }

    #[test]
    fn test_reconstruct_fragments_comprehensive() {
        // Test basic reconstruction with various sizes and fragment counts
        let test_cases = vec![
            (24, 3),               // Basic case
            (25, 3),               // Uneven fragment sizes
            (RPC_MIN_SIZE * 2, 2), // Minimum size fragments
            (RPC_MIN_SIZE * 4, 4), // Small fragments
        ];

        for (message_size, num_fragments) in test_cases {
            let (mut buffer, original_data) =
                generate_rpc_msg_fragments(message_size, num_fragments);
            let batch = RpcBatch::parse_batch(&mut buffer)
                .expect("parse batch failed")
                .expect("no rpc messages found");

            assert_eq!(batch.rpcs.len(), 1);
            let reconstructed = &batch.rpcs[0];

            assert_eq!(reconstructed.len(), RPC_HEADER_SIZE + message_size);

            let header_bytes = &reconstructed[0..4];
            let header = u32::from_be_bytes([
                header_bytes[0],
                header_bytes[1],
                header_bytes[2],
                header_bytes[3],
            ]);
            assert_eq!(header & RPC_LAST_FRAG, RPC_LAST_FRAG);
            assert_eq!(header & RPC_SIZE_MASK, message_size as u32);

            let payload = &reconstructed[RPC_HEADER_SIZE..];
            assert_eq!(payload, &original_data[..]);
        }
    }

    #[test]
    fn test_reconstruct_fragments_large_message() {
        let message_size = 1000;
        let num_fragments = 10;
        let (mut buffer, original_data) = generate_rpc_msg_fragments(message_size, num_fragments);

        let batch = RpcBatch::parse_batch(&mut buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(batch.rpcs.len(), 1);
        let reconstructed = &batch.rpcs[0];
        assert_eq!(reconstructed.len(), RPC_HEADER_SIZE + message_size);

        let payload = &reconstructed[RPC_HEADER_SIZE..];
        assert_eq!(payload, &original_data[..]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_reconstruct_fragments_data_pattern_preservation() {
        let message_size = 256;
        let num_fragments = 5;

        // Create data with a specific pattern
        let original_data: Vec<u8> = (0..message_size).map(|i| (i % 256) as u8).collect();

        // Manually create fragmented buffer to control the data pattern
        let base_fragment_size = original_data.len() / num_fragments;
        let remainder = original_data.len() % num_fragments;
        let mut buffer = BytesMut::new();
        let mut data_offset = 0;

        for i in 0..num_fragments {
            let fragment_size = if i < num_fragments - 1 {
                base_fragment_size
            } else {
                base_fragment_size + remainder
            };

            let fragment_data = &original_data[data_offset..data_offset + fragment_size];
            data_offset += fragment_size;

            let mut header = fragment_size as u32;
            if i == num_fragments - 1 {
                header |= RPC_LAST_FRAG;
            }

            buffer.extend_from_slice(&header.to_be_bytes());
            buffer.extend_from_slice(fragment_data);
        }

        let batch = RpcBatch::parse_batch(&mut buffer)
            .expect("parse batch failed")
            .expect("no rpc messages found");

        assert_eq!(batch.rpcs.len(), 1);
        let reconstructed = &batch.rpcs[0];

        // Verify the data pattern is preserved
        let payload = &reconstructed[RPC_HEADER_SIZE..];
        assert_eq!(payload.len(), original_data.len());
        for (i, (&actual, &expected)) in payload.iter().zip(original_data.iter()).enumerate() {
            assert_eq!(actual, expected, "Data mismatch at position {}", i);
        }
    }
}
