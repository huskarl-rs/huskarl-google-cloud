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
//! - [`kms`] — Cloud KMS signers, verifiers, and AEAD ciphers (asymmetric JWS,
//!   symmetric HMAC and AES), with version pinning and rotation support.
//! - [`secretmanager`] — a `huskarl` secret provider backed by Secret Manager.
//!
//! Each lives behind a cargo feature of the same name.
//!
//! # Guides and explanation
//!
//! The API items here are the **reference** documentation. For task-oriented
//! how-to guides — [signing JWS and serving a
//! JWKS](_docs::guide::asymmetric_signing), [symmetric encryption and
//! HMAC](_docs::guide::symmetric_crypto), [refreshing keys under
//! rotation](_docs::guide::refreshing_keys), and [reading
//! secrets](_docs::guide::secret_manager) — and design explanation ([key
//! versions and rotation](_docs::explanation::versions_and_rotation), [key
//! IDs](_docs::explanation::key_ids), [error
//! handling](_docs::explanation::error_handling)), see the [`_docs`] module.

#[cfg(any(doc, docsrs))]
pub mod _docs;

pub mod kid;
#[cfg(feature = "kms")]
pub mod kms;
#[cfg(feature = "secretmanager")]
pub mod secretmanager;
