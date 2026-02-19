//! Cloud KMS signing with automatic algorithm discovery.

use std::borrow::Cow;

use bon::bon;
use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use huskarl_core::crypto::signer::{JwsSigningKey, SigningKeyMetadata};
use p256::ecdsa::signature;
use snafu::prelude::*;

/// Errors that can occur when creating a key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SetupError {
    /// Failed to retrieve crypto key details.
    GetCryptoKey {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Failed to list crypto key versions.
    ListCryptoKeyVersions {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// No enabled crypto key versions found.
    NoEnabledCryptoKeyVersions,
    /// The specified key uses an unsupported algorithm.
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
    /// The name reported by KMS did not follow the required format.
    InvalidKeyVersionName,
}

/// Errors that can occur when using a key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SigningError {
    /// Failed to sign data with the key.
    AsymmetricSign {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Failed to convert ECDSA signature from DER to fixed format.
    SignatureConversion {
        /// Description of the conversion error.
        source: signature::Error,
    },
    /// Algorithm information mismatch when signing data.
    ///
    /// In this case, key rotation/replacement probably occurred,
    /// and the caller should retry.
    MismatchedAlgorithmInfo,
}

impl huskarl_core::Error for SigningError {
    fn is_retryable(&self) -> bool {
        match self {
            SigningError::AsymmetricSign { source } => source.is_timeout() || source.is_exhausted(),
            SigningError::SignatureConversion { .. } | SigningError::MismatchedAlgorithmInfo => {
                false
            }
        }
    }
}

/// An asymmetric key that supports JWS, stored in Google Cloud KMS.
#[derive(Debug, Clone)]
pub struct AsymmetricJwsKey {
    /// The KMS client used for operations.
    kms_client: KeyManagementService,
    /// The full resource name of the key version.
    resource_name: String,
    /// Information about the algorithm supported by the key.
    key_metadata: SigningKeyMetadata,
}

#[bon]
impl AsymmetricJwsKey {
    async fn resolve_resource_name(
        key_name: &str,
        key_version: Option<String>,
        kms_client: &KeyManagementService,
    ) -> Result<String, SetupError> {
        if let Some(supplied_version) = key_version {
            Ok(supplied_version)
        } else {
            Ok(kms_client
                .list_crypto_key_versions()
                .set_parent(key_name)
                .set_page_size(1)
                .set_filter("state=ENABLED")
                .set_order_by("name desc")
                .send()
                .await
                .context(ListCryptoKeyVersionsSnafu)?
                .crypto_key_versions
                .into_iter()
                .next()
                .ok_or(NoEnabledCryptoKeyVersionsSnafu.build())?
                .name
                .rsplit('/')
                .next()
                .ok_or(InvalidKeyVersionNameSnafu.build())?
                .to_string())
        }
    }

    /// Create a new `AsymmetricJwsKey` from a GCP crypto key.
    ///
    /// If given the resource name of an asymmetric crypto key from KMS,
    /// this will use that key to sign data in a way compatible with JWS/JWA.
    ///
    /// # Examples
    ///
    /// ## Automatic crypto key version discovery
    ///
    /// ```rust,no_run
    /// use google_cloud_kms_v1::client::KeyManagementService;
    /// use huskarl_google_cloud::kms::AsymmetricJwsKey;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
    /// let kms_client = KeyManagementService::builder().build().await?;
    /// let signing_key = AsymmetricJwsKey::builder()
    ///   .key_name("projects/test/locations/us/keyRings/ring/cryptoKeys/key")
    ///   .kms_client(kms_client)
    ///   .build()
    ///   .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Manual crypto key version discovery
    ///
    /// ```rust,no_run
    /// use google_cloud_kms_v1::client::KeyManagementService;
    /// use huskarl_google_cloud::kms::AsymmetricJwsKey;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
    /// let kms_client = KeyManagementService::builder().build().await?;
    /// let signing_key = AsymmetricJwsKey::builder()
    ///   .key_name("projects/test/locations/us/keyRings/ring/cryptoKeys/key")
    ///   .key_version("1")
    ///   .kms_client(kms_client)
    ///   .build()
    ///   .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the key information could not be retrieved,
    /// or the algorithm is not supported.
    #[builder(finish_fn = build)]
    #[allow(clippy::type_complexity)]
    pub async fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The version of the crypto key to use.
        ///
        /// If unset, the latest enabled version is discovered and used.
        #[builder(into)]
        key_version: Option<String>,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// Derive a kid value from the key version.
        #[builder(with = |f: impl Fn(&str) -> String + 'static| Box::new(f))]
        with_kid_from_key_version: Option<Box<dyn FnOnce(&str) -> String>>,
    ) -> Result<Self, SetupError> {
        let resolved_key_version =
            Self::resolve_resource_name(&key_name, key_version, &kms_client).await?;

        let resolved_key_version_name =
            format!("{key_name}/cryptoKeyVersions/{resolved_key_version}");

        let kid = with_kid_from_key_version.map(|f| f(&resolved_key_version));

        let key_metadata = get_signing_key_metadata_for_resource(
            &kms_client,
            &resolved_key_version_name,
            kid.as_deref(),
        )
        .await?;

        Ok(Self {
            kms_client,
            resource_name: resolved_key_version_name,
            key_metadata,
        })
    }
}

impl JwsSigningKey for AsymmetricJwsKey {
    type Error = SigningError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .kms_client
            .asymmetric_sign()
            .set_name(&self.resource_name)
            .set_data(input.to_vec())
            .send()
            .await
            .context(AsymmetricSignSnafu)?;

        // Verify the response came from the expected key version. A mismatch indicates
        // the key was rotated and the caller should reinitialize with the new version.
        ensure!(
            response.name == self.resource_name,
            MismatchedAlgorithmInfoSnafu
        );

        let signature = response.signature.to_vec();

        // For ECDSA, GCP returns DER-encoded signatures but JWT needs fixed-size (r || s)
        match self.key_metadata.jws_algorithm.as_ref() {
            "ES256" => convert_ecdsa_der_to_fixed(&signature, EcDsaVariant::P256)
                .context(SignatureConversionSnafu),
            "ES384" => convert_ecdsa_der_to_fixed(&signature, EcDsaVariant::P384)
                .context(SignatureConversionSnafu),
            _ => Ok(signature),
        }
    }
}

async fn get_signing_key_metadata_for_resource(
    kms_client: &KeyManagementService,
    resource_name: &str,
    kid: Option<&str>,
) -> Result<SigningKeyMetadata, SetupError> {
    let key_version = kms_client
        .get_crypto_key_version()
        .set_name(resource_name)
        .send()
        .await
        .context(GetCryptoKeySnafu)?;

    let jws_algorithm =
        get_jws_algorithm(&key_version.algorithm).with_context(|| UnsupportedAlgorithmSnafu {
            algorithm: key_version.algorithm,
        })?;

    Ok(SigningKeyMetadata::builder()
        .jws_algorithm(jws_algorithm)
        .maybe_key_id(kid)
        .build())
}

fn get_jws_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<&'static str> {
    use CryptoKeyVersionAlgorithm::{
        EcSignEd25519, EcSignP256Sha256, EcSignP384Sha384, RsaSignPkcs12048Sha256,
        RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512,
        RsaSignPss2048Sha256, RsaSignPss3072Sha256, RsaSignPss4096Sha256, RsaSignPss4096Sha512,
    };

    match algorithm {
        // RSA-PSS SHA-256 variants (2048/3072/4096 bit keys)
        RsaSignPss2048Sha256 | RsaSignPss3072Sha256 | RsaSignPss4096Sha256 => Some("PS256"),
        // RSA-PSS SHA-512 variant
        RsaSignPss4096Sha512 => Some("PS512"),
        // RSA PKCS#1 v1.5 SHA-256 variants (2048/3072/4096 bit keys)
        RsaSignPkcs12048Sha256 | RsaSignPkcs13072Sha256 | RsaSignPkcs14096Sha256 => Some("RS256"),
        // RSA PKCS#1 v1.5 SHA-512 variant
        RsaSignPkcs14096Sha512 => Some("RS512"),
        // ECDSA P-256
        EcSignP256Sha256 => Some("ES256"),
        // ECDSA P-384
        EcSignP384Sha384 => Some("ES384"),
        // EdDSA (Ed25519)
        EcSignEd25519 => Some("Ed25519"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EcDsaVariant {
    P256,
    P384,
}

/// Converts a DER-encoded ECDSA signature to fixed-size (r || s) format for JWT.
///
/// GCP KMS returns ECDSA signatures in DER format (ASN.1 SEQUENCE), but JWT/JWS
/// requires IEEE P1363 format (raw r||s concatenation).
///
/// # Errors
///
/// Returns an error if the signature returned by GCP KMS was malformed.
fn convert_ecdsa_der_to_fixed(
    der_sig: &[u8],
    variant: EcDsaVariant,
) -> Result<Vec<u8>, signature::Error> {
    match variant {
        EcDsaVariant::P256 => {
            let sig = p256::ecdsa::Signature::from_der(der_sig)?;
            Ok(sig.to_bytes().to_vec())
        }
        EcDsaVariant::P384 => {
            let sig = p384::ecdsa::Signature::from_der(der_sig)?;
            Ok(sig.to_bytes().to_vec())
        }
    }
}
