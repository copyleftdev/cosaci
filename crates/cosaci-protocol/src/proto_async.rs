//! Async counterparts to `proto::{read_envelope, write_envelope}`
//! (issue #50 follow-on, runtime-rewrite groundwork).
//!
//! The wire framing is **identical** to the sync path —
//! `[4-byte BE length][CBOR bytes]`, capped at
//! [`super::proto::MAX_ENVELOPE_BYTES_PUB`]. The async functions
//! take any `tokio::io::AsyncRead + Unpin` / `AsyncWrite +
//! Unpin` and use `read_exact` / `write_all` / `flush` from
//! `tokio::io::AsyncReadExt` / `AsyncWriteExt`. A buffer
//! produced by `proto::write_envelope` is byte-equal to one
//! produced by `proto_async::write_envelope_async` for the
//! same `Envelope` value, so a sync writer can talk to an
//! async reader and vice-versa — that's the property the
//! tokio rewrite of the coord depends on.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{Envelope, MAX_ENVELOPE_BYTES_PUB};

/// Async-write an `Envelope` as `[4-byte BE length][CBOR bytes]`.
///
/// # Errors
///
/// Returns the underlying writer's I/O error, or
/// `InvalidData` if the encoded envelope exceeds
/// [`super::proto::MAX_ENVELOPE_BYTES_PUB`].
pub async fn write_envelope_async<W: AsyncWrite + Unpin>(
    w: &mut W,
    env: &Envelope,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(env, &mut buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cbor encode: {e}"))
    })?;
    if buf.len() > MAX_ENVELOPE_BYTES_PUB {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("envelope {} > max {}", buf.len(), MAX_ENVELOPE_BYTES_PUB),
        ));
    }
    let len = buf.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Async-read a single `Envelope` from `[4-byte BE length][CBOR bytes]`.
///
/// # Errors
///
/// Returns the reader's I/O error, `InvalidData` for an
/// over-cap declared length, or `InvalidData` for any CBOR
/// decode failure.
pub async fn read_envelope_async<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Envelope> {
    let mut len_bytes = [0_u8; 4];
    r.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_ENVELOPE_BYTES_PUB {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("incoming envelope declared {len} bytes > max {MAX_ENVELOPE_BYTES_PUB}"),
        ));
    }
    let mut buf = vec![0_u8; len];
    r.read_exact(&mut buf).await?;
    ciborium::from_reader::<Envelope, _>(buf.as_slice()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cbor decode: {e}"))
    })
}
