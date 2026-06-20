//! KMS-backed asymmetric JWS signing and public-key (JWKS) serving.
//!
//! - [`signer`] — a [`SigningKey`] that signs JWS via Cloud KMS, pinning a
//!   version per [`VersionStrategy`](super::VersionStrategy).
//! - [`jwks`] — a [`Jwks`] provider that serves the key's public versions to
//!   verifiers.
//!
//! See the [parent module](super) for the version and rotation model.

pub mod jwks;
pub mod signer;

pub use jwks::{Jwks, JwksError};
pub use signer::{KeyVersion, SetupError, SigningError, SigningKey};
