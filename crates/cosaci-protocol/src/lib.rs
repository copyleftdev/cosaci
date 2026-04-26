#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `cosaci-protocol` — wire protocol + TLS transport for CosaCI.
//!
//! `proto` defines the length-prefixed CBOR envelope between coordinator
//! and agent; `tls` wraps `rustls` + `rcgen` for mTLS, including the
//! test CA used by the networked demo. Heavy deps (`rustls`, `rcgen`,
//! `rustls-pemfile`) are isolated here.

pub mod proto;
pub mod proto_async;
pub mod tls;
