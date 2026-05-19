//! Encryption and decryption with symmetric AEAD Cloud KMS keys.

use std::borrow::Cow;
use std::sync::Arc;

use bon::bon;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use huskarl_core::crypto::KeyMatchStrength;
use huskarl_core::crypto::cipher::{
    AeadCipherSelector, AeadDecryptor, AeadEncryptor, AeadOutput, BoxedAeadDecryptor, CipherMatch,
    MultiKeyDecryptor, MultiKeyDecryptorError,
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

/// Errors that can occur when encrypting.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EncryptionError {
    /// Failed to encrypt data with the key.
    RawEncrypt {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Key information in the response did not match the request.
    ///
    /// Key rotation/replacement probably occurred, and the caller should
    /// reinitialize with the new version.
    MismatchedKeyInfo,
}

/// Errors that can occur when decrypting.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DecryptionError {
    /// Failed to decrypt data with the key.
    RawDecrypt {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
}

impl huskarl_core::Error for EncryptionError {
    fn is_retryable(&self) -> bool {
        match self {
            EncryptionError::RawEncrypt { source } => source.is_timeout() || source.is_exhausted(),
            EncryptionError::MismatchedKeyInfo => false,
        }
    }
}

impl huskarl_core::Error for DecryptionError {
    fn is_retryable(&self) -> bool {
        match self {
            DecryptionError::RawDecrypt { source } => source.is_timeout() || source.is_exhausted(),
        }
    }
}

// ─── KeyVersion ──────────────────────────────────────────────────────────────

/// An encryption key bound to a specific Cloud KMS AEAD key version.
///
/// This is the lowest-level cipher primitive: it holds a reference to a
/// specific `CryptoKeyVersion` resource and delegates all raw encrypt/decrypt
/// operations to Cloud KMS.
///
/// Implements [`AeadEncryptor`], [`AeadDecryptor`], and [`AeadCipherSelector`]
/// (selects itself).
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::symmetric::cipher::KeyVersion;
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
    enc_algorithm: String,
    key_id: Option<String>,
}

#[bon]
impl KeyVersion {
    /// Create a new `KeyVersion` from a Cloud KMS AEAD key version resource
    /// name.
    ///
    /// Fetches the key version metadata from KMS to determine the algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the key version metadata could not be retrieved
    /// or the algorithm is not a supported AEAD algorithm.
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

impl AeadCipherSelector for KeyVersion {
    type Encryptor = Self;

    fn select_cipher(&self) -> Self::Encryptor {
        self.clone()
    }
}

impl AeadEncryptor for KeyVersion {
    type Error = EncryptionError;

    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.enc_algorithm)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_id.as_deref().map(Cow::Borrowed)
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        let response = self
            .kms_client
            .raw_encrypt()
            .set_name(&self.resource_name)
            .set_plaintext(plaintext.to_vec())
            .set_additional_authenticated_data(aad.to_vec())
            // initialization_vector is omitted: KMS generates it and returns it
            .send()
            .await
            .context(RawEncryptSnafu)?;

        ensure!(response.name == self.resource_name, MismatchedKeyInfoSnafu);

        let tag_length = usize::try_from(response.tag_length).unwrap_or(0);
        let ct_with_tag = response.ciphertext;

        // The tag is appended to the end of the ciphertext by KMS.
        let split_at = ct_with_tag.len().saturating_sub(tag_length);
        let ciphertext = ct_with_tag[..split_at].to_vec();
        let tag = ct_with_tag[split_at..].to_vec();
        let nonce = response.initialization_vector.to_vec();

        Ok(AeadOutput {
            nonce,
            ciphertext,
            tag,
        })
    }
}

impl AeadDecryptor for KeyVersion {
    type Error = DecryptionError;

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        if let Some(enc) = m.enc
            && enc != self.enc_algorithm
        {
            return None;
        }
        match (m.kid, self.key_id.as_deref()) {
            (Some(jwt_kid), Some(my_kid)) if jwt_kid != my_kid => None,
            (Some(_), Some(_)) => Some(KeyMatchStrength::ByKeyId),
            _ => Some(KeyMatchStrength::ByAlgorithm),
        }
    }

    async fn decrypt(
        &self,
        _cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // KMS RawDecrypt expects the tag appended to the ciphertext.
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        let response = self
            .kms_client
            .raw_decrypt()
            .set_name(&self.resource_name)
            .set_ciphertext(ct_with_tag)
            .set_initialization_vector(nonce.to_vec())
            .set_additional_authenticated_data(aad.to_vec())
            .set_tag_length(i32::try_from(tag.len()).unwrap_or(16))
            .send()
            .await
            .context(RawDecryptSnafu)?;

        Ok(response.plaintext.to_vec())
    }
}

// ─── EncryptionKey ────────────────────────────────────────────────────────────

/// A Cloud KMS AEAD encryption key bound to a specific key version.
///
/// Resolves a key version using the configured [`VersionStrategy`],
/// then delegates encryption to the resolved [`KeyVersion`].
///
/// Implements [`AeadEncryptor`] and [`AeadCipherSelector`].
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::EncryptionKey};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = EncryptionKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .strategy(VersionStrategy::ByLabel("active_version".into()))
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    key_version: KeyVersion,
}

#[bon]
impl EncryptionKey {
    /// Create a new `EncryptionKey` from a Cloud KMS AEAD crypto key resource name.
    ///
    /// Resolves the key version using the configured strategy and fetches its
    /// metadata from KMS.
    ///
    /// # Errors
    ///
    /// Returns an error if version resolution fails, metadata cannot be
    /// retrieved, or the algorithm is not a supported AEAD algorithm.
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
        let key_version = resolve_encryption_key_version(
            &key_name,
            &kms_client,
            &strategy,
            with_kid_from_key_version.as_ref(),
        )
        .await?;
        Ok(Self { key_version })
    }
}

impl AeadCipherSelector for EncryptionKey {
    type Encryptor = KeyVersion;

    fn select_cipher(&self) -> KeyVersion {
        self.key_version.clone()
    }
}

impl AeadEncryptor for EncryptionKey {
    type Error = EncryptionError;

    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.key_version.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_version.key_id()
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        self.key_version.encrypt(plaintext, aad).await
    }
}

// ─── DecryptionKey ────────────────────────────────────────────────────────────

/// A Cloud KMS AEAD decryption key spanning all enabled key versions.
///
/// Implements [`AeadDecryptor`], decrypting against all enabled versions to
/// support key rotation.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::symmetric::cipher::DecryptionKey;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = DecryptionKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DecryptionKey {
    decryptor: Arc<MultiKeyDecryptor>,
}

impl std::fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionKey").finish_non_exhaustive()
    }
}

#[bon]
impl DecryptionKey {
    /// Create a new `DecryptionKey` from a Cloud KMS AEAD crypto key resource name.
    ///
    /// Lists all enabled versions and builds a [`MultiKeyDecryptor`] from them,
    /// enabling rotation-safe decryption.
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
        let versions = resolve_decryption_key_versions(
            &key_name,
            &kms_client,
            with_kid_from_key_version.as_ref(),
            max_versions,
        )
        .await?;
        let decryptor = Arc::new(MultiKeyDecryptor::new(
            versions.into_iter().map(BoxedAeadDecryptor::new).collect(),
        ));
        Ok(Self { decryptor })
    }
}

impl AeadDecryptor for DecryptionKey {
    type Error = MultiKeyDecryptorError;

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryptor.cipher_match(m)
    }

    async fn decrypt(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.decryptor
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
            .await
    }
}

// ─── CipherKey ───────────────────────────────────────────────────────────────

/// A Cloud KMS AEAD key that can both encrypt and decrypt.
///
/// Encrypts with a single version resolved by the configured
/// [`VersionStrategy`], and decrypts with all enabled versions to support
/// key rotation.
///
/// Implements [`AeadEncryptor`], [`AeadCipherSelector`], and [`AeadDecryptor`].
/// Both sides are constructed concurrently.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::CipherKey};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let key = CipherKey::builder()
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .strategy(VersionStrategy::ByLabel("active_version".into()))
///   .build()
///   .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CipherKey {
    encryption: EncryptionKey,
    decryption: DecryptionKey,
}

impl std::fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherKey")
            .field("encryption", &self.encryption)
            .finish_non_exhaustive()
    }
}

#[bon]
impl CipherKey {
    /// Create a new `CipherKey` from a Cloud KMS AEAD crypto key resource name.
    ///
    /// Resolves the encryption version and lists all decryption versions
    /// concurrently.
    ///
    /// # Errors
    ///
    /// Returns an error if version resolution fails, metadata cannot be
    /// retrieved, listing fails, no enabled versions are found, or the
    /// algorithm is not a supported AEAD algorithm.
    #[builder(finish_fn = build)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The version selection strategy for encryption. Defaults to [`VersionStrategy::Latest`].
        #[builder(default)]
        strategy: VersionStrategy,
        /// Derive a kid value from the key version ID.
        #[builder(with = |f: impl Fn(&str) -> String + Send + Sync + 'static| Arc::new(f))]
        with_kid_from_key_version: Option<KidMapper>,
        /// Maximum number of enabled versions to fetch for decryption.
        ///
        /// When set, at most this many versions are fetched (newest-first).
        /// The API `page_size` is set to this value, so a single API call
        /// suffices when the number of enabled versions is within the limit.
        ///
        /// When unset, all enabled versions are fetched (may require multiple
        /// paged requests).
        max_versions: Option<usize>,
    ) -> Result<Self, KeyError> {
        let kid_mapper = with_kid_from_key_version.as_ref();
        let (enc_kv, dec_kvs) = futures_util::try_join!(
            resolve_encryption_key_version(&key_name, &kms_client, &strategy, kid_mapper),
            resolve_decryption_key_versions(&key_name, &kms_client, kid_mapper, max_versions),
        )?;
        let encryption = EncryptionKey {
            key_version: enc_kv,
        };
        let decryption = DecryptionKey {
            decryptor: Arc::new(MultiKeyDecryptor::new(
                dec_kvs.into_iter().map(BoxedAeadDecryptor::new).collect(),
            )),
        };
        Ok(Self {
            encryption,
            decryption,
        })
    }
}

impl AeadCipherSelector for CipherKey {
    type Encryptor = KeyVersion;

    fn select_cipher(&self) -> KeyVersion {
        self.encryption.key_version.clone()
    }
}

impl AeadEncryptor for CipherKey {
    type Error = EncryptionError;

    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.encryption.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.encryption.key_id()
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        self.encryption.encrypt(plaintext, aad).await
    }
}

impl AeadDecryptor for CipherKey {
    type Error = MultiKeyDecryptorError;

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryption.cipher_match(m)
    }

    async fn decrypt(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.decryption
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
            .await
    }
}

// ─── Shared construction ─────────────────────────────────────────────────────

async fn resolve_encryption_key_version(
    key_name: &str,
    kms_client: &KeyManagementService,
    strategy: &VersionStrategy,
    kid_mapper: Option<&KidMapper>,
) -> Result<KeyVersion, KeyError> {
    let version_id = version::resolve_version(key_name, strategy, kms_client)
        .await
        .context(ResolveVersionSnafu)?;

    let resource_name = format!("{key_name}/cryptoKeyVersions/{version_id}");
    let vid = version::version_id_from_resource_name(&resource_name);
    let key_id = kid_mapper.map(|f| f(vid));

    let kv_meta = kms_client
        .get_crypto_key_version()
        .set_name(&resource_name)
        .send()
        .await
        .context(GetCryptoKeyVersionSnafu)?;

    let enc_algorithm = get_enc_algorithm(&kv_meta.algorithm).ok_or_else(|| {
        UnsupportedAlgorithmSnafu {
            algorithm: kv_meta.algorithm,
        }
        .build()
    })?;

    Ok(KeyVersion {
        kms_client: kms_client.clone(),
        resource_name,
        enc_algorithm: enc_algorithm.to_string(),
        key_id,
    })
}

async fn resolve_decryption_key_versions(
    key_name: &str,
    kms_client: &KeyManagementService,
    kid_mapper: Option<&KidMapper>,
    max_versions: Option<usize>,
) -> Result<Vec<KeyVersion>, KeyError> {
    let raw =
        version::list_enabled_kms_versions(kms_client, key_name, max_versions, Some("name desc"))
            .await
            .context(ListCryptoKeyVersionsSnafu)?;

    ensure!(!raw.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

    Ok(raw
        .iter()
        .filter_map(|v| {
            let enc_algorithm = get_enc_algorithm(&v.algorithm)?;
            let vid = version::version_id_from_resource_name(&v.name);
            let key_id = kid_mapper.map(|f| f(vid));
            Some(KeyVersion {
                kms_client: kms_client.clone(),
                resource_name: v.name.clone(),
                enc_algorithm: enc_algorithm.to_string(),
                key_id,
            })
        })
        .collect())
}

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

    let enc_algorithm =
        get_enc_algorithm(&key_version.algorithm).context(setup::UnsupportedAlgorithmSnafu {
            algorithm: key_version.algorithm,
        })?;

    Ok(KeyVersion {
        kms_client,
        resource_name,
        enc_algorithm: enc_algorithm.to_string(),
        key_id,
    })
}

// ─── Algorithm mapping ───────────────────────────────────────────────────────

fn get_enc_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<&'static str> {
    use CryptoKeyVersionAlgorithm::{Aes128Gcm, Aes256Gcm};

    match algorithm {
        Aes128Gcm => Some("A128GCM"),
        Aes256Gcm => Some("A256GCM"),
        _ => None,
    }
}
