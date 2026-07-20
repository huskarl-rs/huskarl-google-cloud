//! Symmetric Cloud KMS key integrations.
//!
//! - [`cipher`] — AEAD raw encrypt/decrypt (`RAW_ENCRYPT_DECRYPT` key purpose)
//! - [`signer`] — HMAC signing and verification (`MAC` key purpose)
//!
//! Encryption and signing pin a single key version; decryption and verification
//! span all enabled versions. See [key versions and
//! rotation](crate::_docs::explanation::versions_and_rotation) for the version
//! and rotation model, and the [symmetric crypto
//! guide](crate::_docs::guide::symmetric_crypto).

pub mod cipher;
pub mod signer;

use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use snafu::prelude::*;

use super::version::VersionResolutionError;

/// Errors that can occur when building a [`cipher::KeyVersion`] or
/// [`signer::KeyVersion`] directly.
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

impl SetupError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            SetupError::GetCryptoKeyVersion { source } => {
                source.is_timeout() || source.is_exhausted()
            }
            SetupError::UnsupportedAlgorithm { .. } => false,
        }
    }
}

impl From<SetupError> for huskarl_core::Error {
    fn from(err: SetupError) -> Self {
        let kind = if err.is_retryable() {
            huskarl_core::ErrorKind::Transport { retryable: true }
        } else {
            huskarl_core::ErrorKind::Crypto
        };
        huskarl_core::Error::new(kind, err)
    }
}

/// Errors that can occur when resolving key versions via the higher-level key
/// builders (e.g. [`cipher::CipherKey`], [`signer::SigningKey`]).
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

impl KeyError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
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

impl From<KeyError> for huskarl_core::Error {
    fn from(err: KeyError) -> Self {
        let kind = if err.is_retryable() {
            huskarl_core::ErrorKind::Transport { retryable: true }
        } else {
            huskarl_core::ErrorKind::Crypto
        };
        huskarl_core::Error::new(kind, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huskarl_core::ErrorKind;

    // Build errors funnel into `huskarl_core::Error` so builders compose as the
    // factory of a `ScheduledRefreshCipher` / `ScheduledRefreshSigner`, whose
    // factory returns `Result<_, huskarl_core::Error>`.

    #[test]
    fn key_error_classifies_by_retryability() {
        // A permanent failure (no enabled versions) is `Crypto`.
        assert!(!KeyError::NoEnabledCryptoKeyVersions.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(KeyError::NoEnabledCryptoKeyVersions).kind(),
            ErrorKind::Crypto
        );
    }

    #[test]
    fn setup_error_classifies_by_retryability() {
        let permanent = SetupError::UnsupportedAlgorithm {
            algorithm: CryptoKeyVersionAlgorithm::default(),
        };
        assert!(!permanent.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(permanent).kind(),
            ErrorKind::Crypto
        );
    }
}
