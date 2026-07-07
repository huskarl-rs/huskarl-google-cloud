#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Google Cloud Platform crypto integrations for `huskarl`.
//!
//! - `kms` — Cloud KMS signers, verifiers, and AEAD ciphers (asymmetric JWS,
//!   symmetric HMAC and AES), with version pinning and rotation support.
//! - `secretmanager` — a `huskarl` secret provider backed by Secret Manager.
//!
//! Each lives behind a cargo feature of the same name.

pub mod kid;
#[cfg(feature = "kms")]
pub mod kms;
#[cfg(feature = "secretmanager")]
pub mod secretmanager;
