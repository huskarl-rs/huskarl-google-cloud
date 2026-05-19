//! Symmetric Cloud KMS key integrations.
//!
//! - [`cipher`] — AEAD raw encrypt/decrypt (`RAW_ENCRYPT_DECRYPT` key purpose)
//! - [`signer`] — HMAC signing and verification (`MAC` key purpose)

pub mod cipher;
pub mod signer;

use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use snafu::prelude::*;

use super::version::VersionResolutionError;

/// Errors that can occur when building a [`KeyVersion`](cipher::KeyVersion) directly.
#[derive(Debug, Snafu)]
#[snafu(module(setup))]
#[non_exhaustive]
pub enum SetupError {
    /// Failed to retrieve the crypto key version metadata.
    GetCryptoKeyVersion {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The specified key uses an unsupported algorithm.
    #[snafu(display("unsupported algorithm {algorithm:?}"))]
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
}

impl huskarl_core::Error for SetupError {
    fn is_retryable(&self) -> bool {
        match self {
            SetupError::GetCryptoKeyVersion { source } => {
                source.is_timeout() || source.is_exhausted()
            }
            SetupError::UnsupportedAlgorithm { .. } => false,
        }
    }
}

/// Errors that can occur when resolving key versions via a `Key`.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyError {
    /// Failed to resolve the primary version via the configured strategy.
    ResolveVersion {
        /// The underlying version resolution error.
        source: VersionResolutionError,
    },
    /// Failed to retrieve key version metadata from KMS.
    GetCryptoKeyVersion {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The key version uses an unsupported algorithm.
    #[snafu(display("unsupported algorithm {algorithm:?}"))]
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
    /// Failed to list enabled key versions.
    ListCryptoKeyVersions {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// No enabled key versions found.
    NoEnabledCryptoKeyVersions,
}

impl huskarl_core::Error for KeyError {
    fn is_retryable(&self) -> bool {
        match self {
            KeyError::ResolveVersion { source } => source.is_retryable(),
            KeyError::GetCryptoKeyVersion { source }
            | KeyError::ListCryptoKeyVersions { source } => {
                source.is_timeout() || source.is_exhausted()
            }
            KeyError::UnsupportedAlgorithm { .. } | KeyError::NoEnabledCryptoKeyVersions => false,
        }
    }
}
