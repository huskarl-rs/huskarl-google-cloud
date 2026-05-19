//! Shared version resolution logic for Cloud KMS keys.

use std::time::{Duration, SystemTime};

use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::CryptoKeyVersion;
use snafu::prelude::*;

/// Extract the trailing version ID segment from a resource name.
///
/// For `"…/cryptoKeyVersions/42"` this returns `"42"`.
#[must_use]
pub fn version_id_from_resource_name(resource_name: &str) -> &str {
    // `rsplit('/').next()` always returns `Some`; if there is no '/' the
    // whole string is returned, which is fine — KMS will reject it if invalid.
    resource_name.rsplit('/').next().unwrap_or(resource_name)
}

/// Errors that can occur during version resolution.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum VersionResolutionError {
    /// Failed to retrieve the crypto key metadata.
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
    /// The name reported by KMS did not follow the required format.
    InvalidKeyVersionName,
    /// The version label was not found on the crypto key.
    VersionLabelNotFound {
        /// The label that was not found.
        label: String,
    },
}

impl huskarl_core::Error for VersionResolutionError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::GetCryptoKey { source } | Self::ListCryptoKeyVersions { source } => {
                source.is_timeout() || source.is_exhausted()
            }
            Self::NoEnabledCryptoKeyVersions
            | Self::InvalidKeyVersionName
            | Self::VersionLabelNotFound { .. } => false,
        }
    }
}

/// Strategy for selecting which key version to use.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum VersionStrategy {
    /// Use a specific version ID.
    Specific(String),
    /// Use the latest enabled version.
    #[default]
    Latest,
    /// Use the version indicated by a label on the `CryptoKey`.
    ///
    /// The label's value is interpreted as the version ID.
    ByLabel(String),
    /// Use the newest enabled version whose `create_time` is at least
    /// `min_age` in the past.
    ///
    /// This is useful during key rotation: a freshly-created version is
    /// skipped until it has had time to propagate or be validated.  If no
    /// version meets the age threshold (e.g. only one version exists and
    /// it is brand-new), the newest enabled version is used as a fallback.
    MinAge(Duration),
}

/// Resolve a version ID from a key name using the given strategy.
///
/// # Errors
///
/// Returns an error if the version could not be resolved from KMS.
pub async fn resolve_version(
    key_name: &str,
    strategy: &VersionStrategy,
    kms_client: &KeyManagementService,
) -> Result<String, VersionResolutionError> {
    match strategy {
        VersionStrategy::Specific(version) => Ok(version.clone()),
        VersionStrategy::Latest => resolve_latest_version(key_name, kms_client).await,
        VersionStrategy::ByLabel(label) => {
            resolve_version_by_label(key_name, kms_client, label).await
        }
        VersionStrategy::MinAge(min_age) => {
            resolve_min_age_version(key_name, kms_client, min_age).await
        }
    }
}

async fn resolve_latest_version(
    key_name: &str,
    kms_client: &KeyManagementService,
) -> Result<String, VersionResolutionError> {
    kms_client
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
        .ok_or(InvalidKeyVersionNameSnafu.build())
        .map(String::from)
}

async fn resolve_min_age_version(
    key_name: &str,
    kms_client: &KeyManagementService,
    min_age: &Duration,
) -> Result<String, VersionResolutionError> {
    let versions = list_enabled_kms_versions(kms_client, key_name, None, Some("name desc"))
        .await
        .context(ListCryptoKeyVersionsSnafu)?;

    ensure!(!versions.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

    Ok(select_min_age_id(&versions, min_age).to_string())
}

/// Fetch all enabled `CryptoKeyVersion`s for `key_name`, handling pagination.
///
/// Returns the raw API error on failure; callers should `.context(…)` it into
/// their own error type.
pub(crate) async fn list_enabled_kms_versions(
    kms_client: &KeyManagementService,
    key_name: &str,
    max_versions: Option<usize>,
    order_by: Option<&str>,
) -> Result<Vec<CryptoKeyVersion>, google_cloud_kms_v1::Error> {
    let mut all = Vec::new();
    let mut page_token = String::new();

    loop {
        let remaining = max_versions.map(|m| m.saturating_sub(all.len()));
        if remaining == Some(0) {
            break;
        }

        let mut request = kms_client
            .list_crypto_key_versions()
            .set_parent(key_name)
            .set_filter("state=ENABLED");

        if let Some(order) = order_by {
            request = request.set_order_by(order);
        }

        if let Some(n) = remaining {
            request = request.set_page_size(i32::try_from(n).unwrap_or(i32::MAX));
        }

        if !page_token.is_empty() {
            request = request.set_page_token(&page_token);
        }

        let response = request.send().await?;
        all.extend(response.crypto_key_versions);

        if response.next_page_token.is_empty() || max_versions.is_some_and(|m| all.len() >= m) {
            break;
        }
        page_token = response.next_page_token;
    }

    Ok(all)
}

/// Select the version ID from an ordered (newest-first) list using the
/// [`VersionStrategy::MinAge`] strategy.
///
/// Returns the newest version whose `create_time` is at least `min_age` in
/// the past, falling back to the newest version if none meet the threshold.
pub(crate) fn select_min_age_id<'a>(
    versions: &'a [CryptoKeyVersion],
    min_age: &Duration,
) -> &'a str {
    let cutoff = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default() // only fails if the system clock is before the Unix epoch
        .as_secs()
        .cast_signed()
        - min_age.as_secs().cast_signed();

    let chosen = versions
        .iter()
        .find(|v| {
            v.create_time
                .as_ref()
                .is_some_and(|ct| ct.seconds() <= cutoff)
        })
        // Fall back to the newest version if none meet the threshold.
        .unwrap_or(&versions[0]);

    version_id_from_resource_name(&chosen.name)
}

async fn resolve_version_by_label(
    key_name: &str,
    kms_client: &KeyManagementService,
    label: &str,
) -> Result<String, VersionResolutionError> {
    let crypto_key = kms_client
        .get_crypto_key()
        .set_name(key_name)
        .send()
        .await
        .context(GetCryptoKeySnafu)?;

    crypto_key
        .labels
        .get(label)
        .cloned()
        .context(VersionLabelNotFoundSnafu { label })
}
