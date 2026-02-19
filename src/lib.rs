#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]

//! Google Cloud Platform crypto integrations.
//!
//! Implements `huskarl` traits for GCP services.

#[cfg(feature = "kms")]
pub mod kms;
#[cfg(feature = "secretmanager")]
pub mod secretmanager;
