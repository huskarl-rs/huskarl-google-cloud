//! Signing and verification with symmetric (HMAC) Cloud KMS keys.

use std::borrow::Cow;
use std::sync::Arc;

use bon::bon;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use huskarl_core::BoxedError;
use huskarl_core::crypto::KeyMatchStrength;
use huskarl_core::crypto::signer::{JwsSigner, JwsSignerSelector};
use huskarl_core::crypto::verifier::{
    BoxedJwsVerifier, JwsVerifier, KeyMatch, MultiKeyVerifier, VerifyError,
};
use snafu::prelude::*;

use super::super::version::{self, VersionStrategy};
use super::setup;
use super::{
    GetCryptoKeyVersionSnafu, ListCryptoKeyVersionsSnafu, NoEnabledCryptoKeyVersionsSnafu,
    ResolveVersionSnafu, UnsupportedAlgorithmSnafu,
};
pub use super::{KeyError, SetupError};

type KidMapper = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Errors that can occur when signing.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SigningError {
    /// Failed to sign data with the key.
    MacSign {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Key information in the response did not match the request.
    ///
    /// Key rotation/replacement probably occurred, and the caller should
    /// reinitialize with the new version.
    MismatchedKeyInfo,
}

/// Errors that can occur when verifying.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum VerificationError {
    /// Failed to verify data with the key.
    MacVerify {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
}

impl huskarl_core::Error for VerificationError {
    fn is_retryable(&self) -> bool {
        match self {
            VerificationError::MacVerify { source } => source.is_timeout() || source.is_exhausted(),
        }
    }
}

impl huskarl_core::Error for SigningError {
    fn is_retryable(&self) -> bool {
        match self {
            SigningError::MacSign { source } => source.is_timeout() || source.is_exhausted(),
            SigningError::MismatchedKeyInfo => false,
        }
    }
}

// ─── KeyVersion ──────────────────────────────────────────────────────────────

/// A signing key bound to a specific Cloud KMS HMAC key version.
///
/// This is the lowest-level signing primitive: it holds a reference to a
/// specific `CryptoKeyVersion` resource and delegates all MAC signing
/// operations to Cloud KMS.
///
/// Implements [`JwsSigner`], [`JwsSignerSelector`] (selects itself), and
/// [`JwsVerifier`].
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::symmetric::signer::KeyVersion;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = KeyVersion::builder()
///   .resource_name("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
///   .kms_client(kms_client)
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KeyVersion {
    kms_client: KeyManagementService,
    resource_name: String,
    jws_algorithm: String,
    key_id: Option<String>,
}

#[bon]
impl KeyVersion {
    /// Create a new `KeyVersion` from a Cloud KMS HMAC key version resource name.
    ///
    /// Fetches the key version metadata from KMS to determine the algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata could not be retrieved or the algorithm
    /// is not a supported HMAC variant.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key version.
        #[builder(into)]
        resource_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// Derive a kid value from the key version ID.
        #[builder(with = |f: impl Fn(&str) -> String + Send + Sync + 'static| Arc::new(f))]
        with_kid_from_key_version: Option<KidMapper>,
    ) -> Result<Self, SetupError> {
        build_key_version(resource_name, kms_client, with_kid_from_key_version).await
    }
}

impl JwsSignerSelector for KeyVersion {
    type Signer = Self;

    fn select_signer(&self) -> Self::Signer {
        self.clone()
    }
}

impl JwsSigner for KeyVersion {
    type Error = SigningError;

    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.jws_algorithm)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_id.as_deref().map(Cow::Borrowed)
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .kms_client
            .mac_sign()
            .set_name(&self.resource_name)
            .set_data(input.to_vec())
            .send()
            .await
            .context(MacSignSnafu)?;

        ensure!(response.name == self.resource_name, MismatchedKeyInfoSnafu);

        Ok(response.mac.to_vec())
    }
}

impl JwsVerifier for KeyVersion {
    type Error = VerificationError;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        if key_match.alg != self.jws_algorithm {
            return None;
        }
        match (key_match.kid, self.key_id.as_deref()) {
            (Some(jwt_kid), Some(my_kid)) if jwt_kid != my_kid => None,
            (Some(_), Some(_)) => Some(KeyMatchStrength::ByKeyId),
            _ => Some(KeyMatchStrength::ByAlgorithm),
        }
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        _key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        let response = self
            .kms_client
            .mac_verify()
            .set_name(&self.resource_name)
            .set_data(input.to_vec())
            .set_mac(signature.to_vec())
            .send()
            .await
            .context(MacVerifySnafu)
            .map_err(|source| VerifyError::Other { source })?;

        if response.success {
            Ok(())
        } else {
            Err(VerifyError::SignatureMismatch)
        }
    }
}

// ─── SigningKey ───────────────────────────────────────────────────────────────

/// A Cloud KMS HMAC signing key bound to a specific key version.
///
/// Implements [`JwsSigner`] and [`JwsSignerSelector`].
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::{VersionStrategy, symmetric::signer::SigningKey};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = SigningKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .strategy(VersionStrategy::ByLabel("active".into()))
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SigningKey {
    key_version: KeyVersion,
}

#[bon]
impl SigningKey {
    /// Create a new `SigningKey` from a Cloud KMS HMAC crypto key resource name.
    ///
    /// Resolves the primary version using the configured strategy, then fetches
    /// its metadata from KMS.
    ///
    /// # Errors
    ///
    /// Returns an error if version resolution fails, metadata cannot be retrieved,
    /// or the algorithm is not a supported HMAC variant.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The version selection strategy. Defaults to [`VersionStrategy::Latest`].
        #[builder(default)]
        strategy: VersionStrategy,
        /// Derive a kid value from the key version ID.
        #[builder(with = |f: impl Fn(&str) -> String + Send + Sync + 'static| Arc::new(f))]
        with_kid_from_key_version: Option<KidMapper>,
    ) -> Result<Self, KeyError> {
        let version_id = version::resolve_version(&key_name, &strategy, &kms_client)
            .await
            .context(ResolveVersionSnafu)?;

        let resource_name = format!("{key_name}/cryptoKeyVersions/{version_id}");
        let vid = version::version_id_from_resource_name(&resource_name);
        let key_id = with_kid_from_key_version.as_ref().map(|f| f(vid));

        let kv_meta = kms_client
            .get_crypto_key_version()
            .set_name(&resource_name)
            .send()
            .await
            .context(GetCryptoKeyVersionSnafu)?;

        let jws_algorithm = get_jws_algorithm(&kv_meta.algorithm).ok_or_else(|| {
            UnsupportedAlgorithmSnafu {
                algorithm: kv_meta.algorithm,
            }
            .build()
        })?;

        Ok(Self {
            key_version: KeyVersion {
                kms_client,
                resource_name,
                jws_algorithm: jws_algorithm.to_string(),
                key_id,
            },
        })
    }
}

impl JwsSignerSelector for SigningKey {
    type Signer = KeyVersion;

    fn select_signer(&self) -> KeyVersion {
        self.key_version.clone()
    }
}

impl JwsSigner for SigningKey {
    type Error = SigningError;

    fn jws_algorithm(&self) -> Cow<'_, str> {
        self.key_version.jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_version.key_id()
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.key_version.sign(input).await
    }
}

// ─── VerifyingKey ─────────────────────────────────────────────────────────────

/// A Cloud KMS HMAC verifying key spanning all enabled key versions.
///
/// Implements [`JwsVerifier`], verifying against all enabled versions to
/// support key rotation.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::symmetric::signer::VerifyingKey;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = VerifyingKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    verifier: Arc<MultiKeyVerifier>,
}

#[bon]
impl VerifyingKey {
    /// Create a new `VerifyingKey` from a Cloud KMS HMAC crypto key resource name.
    ///
    /// Lists all enabled versions and builds a [`MultiKeyVerifier`] from them,
    /// enabling rotation-safe verification.
    ///
    /// # Errors
    ///
    /// Returns an error if listing fails or no enabled versions are found.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// Derive a kid value from the key version ID.
        #[builder(with = |f: impl Fn(&str) -> String + Send + Sync + 'static| Arc::new(f))]
        with_kid_from_key_version: Option<KidMapper>,
        /// Maximum number of enabled versions to fetch.
        ///
        /// When set, at most this many versions are fetched (newest-first).
        /// The API `page_size` is set to this value, so a single API call
        /// suffices when the number of enabled versions is within the limit.
        ///
        /// When unset, all enabled versions are fetched (may require multiple
        /// paged requests).
        max_versions: Option<usize>,
    ) -> Result<Self, KeyError> {
        let raw = version::list_enabled_kms_versions(
            &kms_client,
            &key_name,
            max_versions,
            Some("name desc"),
        )
        .await
        .context(ListCryptoKeyVersionsSnafu)?;
        ensure!(!raw.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

        let versions: Vec<KeyVersion> = raw
            .iter()
            .filter_map(|v| {
                let jws_algorithm = get_jws_algorithm(&v.algorithm)?;
                let vid = version::version_id_from_resource_name(&v.name);
                let key_id = with_kid_from_key_version.as_ref().map(|f| f(vid));
                Some(KeyVersion {
                    kms_client: kms_client.clone(),
                    resource_name: v.name.clone(),
                    jws_algorithm: jws_algorithm.to_string(),
                    key_id,
                })
            })
            .collect();

        let verifier = Arc::new(
            MultiKeyVerifier::new(versions.into_iter().map(BoxedJwsVerifier::new).collect())
                .try_all_on_ambiguous_match(true),
        );

        Ok(Self { verifier })
    }
}

impl JwsVerifier for VerifyingKey {
    type Error = BoxedError;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.verifier.key_match(key_match)
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        self.verifier.verify(input, signature, key_match).await
    }
}

// ─── Shared construction ─────────────────────────────────────────────────────

async fn build_key_version(
    resource_name: String,
    kms_client: KeyManagementService,
    with_kid_from_key_version: Option<KidMapper>,
) -> Result<KeyVersion, SetupError> {
    let version_id = version::version_id_from_resource_name(&resource_name);
    let key_id = with_kid_from_key_version.map(|f| f(version_id));

    let key_version = kms_client
        .get_crypto_key_version()
        .set_name(&resource_name)
        .send()
        .await
        .context(setup::GetCryptoKeyVersionSnafu)?;

    let jws_algorithm =
        get_jws_algorithm(&key_version.algorithm).context(setup::UnsupportedAlgorithmSnafu {
            algorithm: key_version.algorithm,
        })?;

    Ok(KeyVersion {
        kms_client,
        resource_name,
        jws_algorithm: jws_algorithm.to_string(),
        key_id,
    })
}

// ─── Algorithm mapping ───────────────────────────────────────────────────────

fn get_jws_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<&'static str> {
    use CryptoKeyVersionAlgorithm::{HmacSha256, HmacSha384, HmacSha512};

    match algorithm {
        HmacSha256 => Some("HS256"),
        HmacSha384 => Some("HS384"),
        HmacSha512 => Some("HS512"),
        _ => None,
    }
}
