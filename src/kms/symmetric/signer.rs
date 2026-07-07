//! Signing and verification with symmetric (HMAC) Cloud KMS keys.

use std::borrow::Cow;
use std::sync::Arc;

use bon::bon;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use huskarl_core::crypto::KeyMatchStrength;
use huskarl_core::crypto::signer::{JwsSigner, JwsSignerSelector};
use huskarl_core::crypto::verifier::{JwsVerifier, KeyMatch, MultiKeyVerifier, VerifyError};
use huskarl_core::platform::MaybeSendBoxFuture;
use snafu::prelude::*;

use super::super::version::{self, VersionStrategy};
use super::setup;
use super::{
    GetCryptoKeyVersionSnafu, ListCryptoKeyVersionsSnafu, NoEnabledCryptoKeyVersionsSnafu,
    ResolveVersionSnafu, UnsupportedAlgorithmSnafu,
};
pub use super::{KeyError, SetupError};

use crate::kid::VersionKid;

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

impl VerificationError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            VerificationError::MacVerify { source } => source.is_timeout() || source.is_exhausted(),
        }
    }
}

impl From<VerificationError> for huskarl_core::Error {
    fn from(err: VerificationError) -> Self {
        let kind = if err.is_retryable() {
            huskarl_core::ErrorKind::Transport { retryable: true }
        } else {
            huskarl_core::ErrorKind::Crypto
        };
        huskarl_core::Error::new(kind, err)
    }
}

impl SigningError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            SigningError::MacSign { source } => source.is_timeout() || source.is_exhausted(),
            SigningError::MismatchedKeyInfo => false,
        }
    }
}

impl From<SigningError> for huskarl_core::Error {
    fn from(err: SigningError) -> Self {
        let kind = if err.is_retryable() {
            huskarl_core::ErrorKind::Transport { retryable: true }
        } else {
            huskarl_core::ErrorKind::Crypto
        };
        huskarl_core::Error::new(kind, err)
    }
}

// ─── KeyVersion ──────────────────────────────────────────────────────────────

/// A signing key bound to a specific Cloud KMS HMAC key version.
///
/// This is the lowest-level signing primitive: it holds a reference to a
/// specific `CryptoKeyVersion` resource and delegates MAC signing and
/// verification to Cloud KMS.
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
        /// How to derive a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
    ) -> Result<Self, SetupError> {
        build_key_version(resource_name, kms_client, kid).await
    }
}

impl JwsSignerSelector for KeyVersion {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = Arc::new(self.clone());
        Box::pin(async move { signer })
    }
}

impl JwsSigner for KeyVersion {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.jws_algorithm)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_id.as_deref().map(Cow::Borrowed)
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, huskarl_core::Error>> {
        Box::pin(async move {
            let response = self
                .kms_client
                .mac_sign()
                .set_name(&self.resource_name)
                .set_data(input.to_vec())
                .send()
                .await
                .context(MacSignSnafu)?;

            if response.name != self.resource_name {
                return Err(SigningError::MismatchedKeyInfo.into());
            }

            Ok(response.mac.to_vec())
        })
    }
}

impl JwsVerifier for KeyVersion {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        key_match.strength_for(&[&self.jws_algorithm], self.key_id.as_deref())
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        _key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
            let response = self
                .kms_client
                .mac_verify()
                .set_name(&self.resource_name)
                .set_data(input.to_vec())
                .set_mac(signature.to_vec())
                .send()
                .await
                .context(MacVerifySnafu)
                .map_err(huskarl_core::Error::from)?;

            if response.success {
                Ok(())
            } else {
                Err(VerifyError::SignatureMismatch)
            }
        })
    }
}

// ─── SigningKey ───────────────────────────────────────────────────────────────

/// A Cloud KMS HMAC signing key.
///
/// Resolves a single key version using the configured [`VersionStrategy`] at
/// build time, then signs JWS with it via Cloud KMS. Implements [`JwsSigner`]
/// and [`JwsSignerSelector`].
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
        /// How to derive a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
    ) -> Result<Self, KeyError> {
        let version_id = version::resolve_version(&key_name, &strategy, &kms_client)
            .await
            .context(ResolveVersionSnafu)?;

        let resource_name = format!("{key_name}/cryptoKeyVersions/{version_id}");

        let kv_response = kms_client
            .get_crypto_key_version()
            .set_name(&resource_name)
            .send()
            .await
            .context(GetCryptoKeyVersionSnafu)?;

        // Use the canonical name from the response to resolve aliases.
        let resolved_name = if kv_response.name.is_empty() {
            resource_name
        } else {
            kv_response.name
        };
        let vid = version::version_id_from_resource_name(&resolved_name);
        let key_id = kid.derive(vid);

        let jws_algorithm = get_jws_algorithm(&kv_response.algorithm).ok_or_else(|| {
            UnsupportedAlgorithmSnafu {
                algorithm: kv_response.algorithm,
            }
            .build()
        })?;

        Ok(Self {
            key_version: KeyVersion {
                kms_client,
                resource_name: resolved_name,
                jws_algorithm: jws_algorithm.to_string(),
                key_id,
            },
        })
    }
}

impl JwsSignerSelector for SigningKey {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = Arc::new(self.key_version.clone());
        Box::pin(async move { signer })
    }
}

impl JwsSigner for SigningKey {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        self.key_version.jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_version.key_id()
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, huskarl_core::Error>> {
        self.key_version.sign(input)
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
        /// How to derive a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
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
                let key_id = kid.derive(vid);
                Some(KeyVersion {
                    kms_client: kms_client.clone(),
                    resource_name: v.name.clone(),
                    jws_algorithm: jws_algorithm.to_string(),
                    key_id,
                })
            })
            .collect();

        let verifier = Arc::new(
            MultiKeyVerifier::new(
                versions
                    .into_iter()
                    .map(|v| Arc::new(v) as Arc<dyn JwsVerifier>)
                    .collect(),
            )
            .try_all_on_ambiguous_match(true),
        );

        Ok(Self { verifier })
    }
}

impl JwsVerifier for VerifyingKey {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.verifier.key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        self.verifier.verify(input, signature, key_match)
    }
}

// ─── Shared construction ─────────────────────────────────────────────────────

async fn build_key_version(
    resource_name: String,
    kms_client: KeyManagementService,
    kid: VersionKid,
) -> Result<KeyVersion, SetupError> {
    let kv_response = kms_client
        .get_crypto_key_version()
        .set_name(&resource_name)
        .send()
        .await
        .context(setup::GetCryptoKeyVersionSnafu)?;

    // Use the canonical name from the response to resolve aliases.
    let resolved_name = if kv_response.name.is_empty() {
        resource_name
    } else {
        kv_response.name
    };
    let version_id = version::version_id_from_resource_name(&resolved_name);
    let key_id = kid.derive(version_id);

    let jws_algorithm =
        get_jws_algorithm(&kv_response.algorithm).context(setup::UnsupportedAlgorithmSnafu {
            algorithm: kv_response.algorithm,
        })?;

    Ok(KeyVersion {
        kms_client,
        resource_name: resolved_name,
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::future::Future;

    use google_cloud_gax::Result as GaxResult;
    use google_cloud_gax::options::RequestOptions;
    use google_cloud_gax::response::Response;
    use google_cloud_kms_v1::model::{
        MacSignRequest, MacSignResponse, MacVerifyRequest, MacVerifyResponse,
    };
    use google_cloud_kms_v1::stub::KeyManagementService as KmsStub;
    use huskarl_core::ErrorKind;
    use rstest::rstest;

    use super::*;

    const RESOURCE: &str = "projects/p/.../cryptoKeyVersions/1";

    #[derive(Debug, Clone, Default)]
    struct MockKms {
        response_name: String,
        mac: Vec<u8>,
        verify_success: bool,
    }

    impl KmsStub for MockKms {
        fn mac_sign(
            &self,
            _req: MacSignRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<MacSignResponse>>> + Send {
            let resp = MacSignResponse::default()
                .set_name(self.response_name.clone())
                .set_mac(self.mac.clone());
            async move { Ok(Response::from(resp)) }
        }

        fn mac_verify(
            &self,
            _req: MacVerifyRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<MacVerifyResponse>>> + Send {
            let resp = MacVerifyResponse::default().set_success(self.verify_success);
            async move { Ok(Response::from(resp)) }
        }
    }

    fn key_version(mock: MockKms, jws_algorithm: &str, key_id: Option<&str>) -> KeyVersion {
        KeyVersion {
            kms_client: KeyManagementService::from_stub(mock),
            resource_name: RESOURCE.to_owned(),
            jws_algorithm: jws_algorithm.to_owned(),
            key_id: key_id.map(str::to_owned),
        }
    }

    #[rstest]
    #[case(CryptoKeyVersionAlgorithm::HmacSha256, Some("HS256"))]
    #[case(CryptoKeyVersionAlgorithm::HmacSha384, Some("HS384"))]
    #[case(CryptoKeyVersionAlgorithm::HmacSha512, Some("HS512"))]
    #[case(CryptoKeyVersionAlgorithm::Aes256Gcm, None)]
    fn get_jws_algorithm_maps_hmac_algorithms(
        #[case] algorithm: CryptoKeyVersionAlgorithm,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(get_jws_algorithm(&algorithm), expected);
    }

    #[test]
    fn signing_error_classifies_as_crypto() {
        let err = SigningError::MismatchedKeyInfo;
        assert!(!err.is_retryable());
        assert_eq!(huskarl_core::Error::from(err).kind(), ErrorKind::Crypto);
    }

    #[rstest]
    #[case("HS256", Some("k1"), Some("k1"), Some(KeyMatchStrength::ByKeyId))]
    #[case("HS256", None, Some("k1"), Some(KeyMatchStrength::ByAlgorithm))]
    #[case("HS256", Some("k2"), Some("k1"), None)]
    #[case("HS384", Some("k1"), Some("k1"), None)] // alg mismatch
    #[case("HS256", None, None, Some(KeyMatchStrength::ByAlgorithm))]
    fn key_match_applies_alg_and_kid_rules(
        #[case] req_alg: &str,
        #[case] req_kid: Option<&str>,
        #[case] registered_kid: Option<&str>,
        #[case] expected: Option<KeyMatchStrength>,
    ) {
        let kv = key_version(MockKms::default(), "HS256", registered_kid);
        let m = KeyMatch::builder().alg(req_alg).maybe_kid(req_kid).build();
        assert_eq!(kv.key_match(&m), expected);
    }

    #[tokio::test]
    async fn sign_returns_the_mac() {
        let mock = MockKms {
            response_name: RESOURCE.to_owned(),
            mac: vec![0xAA, 0xBB, 0xCC],
            ..Default::default()
        };
        let kv = key_version(mock, "HS256", None);
        assert_eq!(kv.sign(b"data").await.unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[tokio::test]
    async fn sign_rejects_mismatched_key_name() {
        let mock = MockKms {
            response_name: "projects/p/.../cryptoKeyVersions/2".to_owned(),
            mac: vec![1],
            ..Default::default()
        };
        let kv = key_version(mock, "HS256", None);
        let err = kv.sign(b"data").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Crypto);
    }

    #[tokio::test]
    async fn verify_accepts_a_successful_mac() {
        let mock = MockKms {
            verify_success: true,
            ..Default::default()
        };
        let kv = key_version(mock, "HS256", None);
        let m = KeyMatch::builder().alg("HS256").build();
        assert!(kv.verify(b"data", b"sig", &m).await.is_ok());
    }

    #[tokio::test]
    async fn verify_reports_signature_mismatch() {
        let mock = MockKms {
            verify_success: false,
            ..Default::default()
        };
        let kv = key_version(mock, "HS256", None);
        let m = KeyMatch::builder().alg("HS256").build();
        assert!(matches!(
            kv.verify(b"data", b"sig", &m).await,
            Err(VerifyError::SignatureMismatch)
        ));
    }
}
