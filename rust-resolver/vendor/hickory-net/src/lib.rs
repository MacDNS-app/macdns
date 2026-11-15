// SPDX-FileCopyrightText: 2026 Marcus Grando
// SPDX-License-Identifier: MIT OR Apache-2.0
// Modified for MacDNS. See rust-resolver/vendor/README.md.

//! Networking library for Hickory DNS

#![warn(clippy::dbg_macro, clippy::print_stdout, missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use hickory_proto as proto;

pub mod client;

#[cfg(feature = "__dnssec")]
pub mod dnssec;

mod error;
pub use error::{
    DnsError, ExtendedErrors, ForwardNSData, NetError, NoRecords, MAX_EXTENDED_ERRORS,
    MAX_EXTENDED_ERROR_LEN,
};

#[cfg(feature = "__https")]
pub mod h2;
#[cfg(feature = "__h3")]
pub mod h3;
#[cfg(any(feature = "__https", feature = "__h3"))]
pub mod http;
#[cfg(feature = "mdns")]
pub mod multicast;
#[cfg(all(feature = "__quic", feature = "tokio"))]
pub mod quic;
pub mod runtime;
pub mod tcp;
#[cfg(feature = "__tls")]
pub mod tls;
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::BufDnsStreamHandle;
#[doc(hidden)]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
