use bon::Builder;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::secrets::{Secret, SecretDecoder, SecretOutput};
use snafu::prelude::*;

use super::SecretVersion;

/// Errors that can occur when listing secret versions.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretVersionsError {
    /// Failed to retrieve the secret version metadata.
    GetSecretVersion {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// Failed to list secret versions.
    ListSecretVersions {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// No enabled secret versions found.
    NoEnabledSecretVersions,
    /// The primary version is not among the enabled versions.
    ///
    /// This can occur if the version referenced by the primary alias is
    /// disabled or does not exist.
    PrimaryVersionNotFound,
}

impl SecretVersionsError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::GetSecretVersion { source } | Self::ListSecretVersions { source } => {
                source.is_exhausted() || source.is_timeout()
            }
            Self::NoEnabledSecretVersions | Self::PrimaryVersionNotFound => false,
        }
    }
}

/// The resolved secret versions returned by [`SecretVersions::all`].
///
/// `primary` is guaranteed to be present in `all`.
pub struct ActiveSecretVersions<D: SecretDecoder> {
    /// The version identified by the configured primary alias.
    /// Use this for encryption.
    pub primary: SecretVersion<D>,
    /// All enabled versions, including `primary`. Use this alongside
    /// a caller-supplied cipher factory to build a
    /// [`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor)
    /// so that data encrypted with any enabled version can be decrypted
    /// during key rotation.
    pub all: Vec<SecretVersion<D>>,
}

impl<D: SecretDecoder> ActiveSecretVersions<D> {
    /// Fetch the secret values for the primary version and all enabled
    /// versions concurrently.
    ///
    /// Returns `(primary_value, all_values)`. The primary value is also
    /// present somewhere in `all_values` (the order matches [`all`](Self::all)).
    ///
    /// # Errors
    ///
    /// Returns an error if any secret value fetch fails.
    pub async fn get_all_values(
        &self,
    ) -> Result<(SecretOutput<D::Output>, Vec<SecretOutput<D::Output>>), huskarl_core::Error> {
        futures_util::future::try_join(
            self.primary.get_secret_value(),
            futures_util::future::try_join_all(
                self.all
                    .iter()
                    .map(huskarl_core::secrets::Secret::get_secret_value),
            ),
        )
        .await
    }
}

/// A multi-version handle for a Google Cloud Secret Manager secret.
///
/// Provides access to both a designated primary version (via a configured
/// alias) and all enabled versions of the secret. Intended for use with
/// key rotation: the primary alias is updated externally to promote a new
/// key after it has propagated to all consumers.
///
/// Holds no cached state — caching is handled by the caller.
///
/// # Key rotation pattern
///
/// 1. Add a new secret version.
/// 2. Wait for all servers to pick it up via [`all`](Self::all)
///    and a [`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor).
/// 3. Update the primary alias to point to the new version.
/// 4. Servers will now encrypt with the new key on next refresh.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_secretmanager_v1::client::SecretManagerService;
/// use huskarl_core::secrets::encodings::BinaryEncoding;
/// use huskarl_google_cloud::secretmanager::SecretVersions;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = SecretManagerService::builder().build().await?;
/// let sv = SecretVersions::builder()
///     .decoder(BinaryEncoding)
///     .client(client)
///     .secret_name("projects/p/secrets/my-aes-key")
///     .primary_alias("active")
///     .build();
///
/// // Atomic snapshot: primary confirmed present in all enabled versions.
/// let active = sv.all().await?;
/// let (primary_val, all_vals) = active.get_all_values().await?;
/// // Map primary_val and all_vals through a caller-supplied cipher factory.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretVersions<D: SecretDecoder> {
    /// The decoder applied to the secret data.
    decoder: D,
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret resource name (e.g. `projects/p/secrets/my-key`).
    #[builder(into)]
    secret_name: String,
    /// The version alias used to identify the primary version
    /// (e.g. `"active"`, `"current"`).
    #[builder(into)]
    primary_alias: String,
    /// Maximum number of enabled versions to return from [`all`](SecretVersions::all)
    /// and [`get_secrets`](SecretVersions::get_secrets).
    ///
    /// When set, at most this many versions are fetched (newest-first).
    /// The API `page_size` is set to this value, so a single API call
    /// suffices when the number of enabled versions is within the limit.
    ///
    /// When unset, all enabled versions are fetched (may require multiple
    /// paged requests).
    max_versions: Option<usize>,
}

impl<D: SecretDecoder + Clone> SecretVersions<D> {
    /// Returns a handle to the primary secret version.
    ///
    /// This is a synchronous operation — it constructs a [`SecretVersion`]
    /// pointing at `{secret_name}/versions/{primary_alias}` without making
    /// any API calls. The secret value is fetched lazily when
    /// [`get_secret_value`](huskarl_core::secrets::Secret::get_secret_value)
    /// is called on the returned handle.
    pub fn get_primary_secret(&self) -> SecretVersion<D> {
        SecretVersion::builder()
            .decoder(self.decoder.clone())
            .client(self.client.clone())
            .resource_name(format!(
                "{}/versions/{}",
                self.secret_name, self.primary_alias
            ))
            .build()
    }

    /// Returns handles to all enabled versions of the secret.
    ///
    /// Lists all versions with state `ENABLED` and returns a [`SecretVersion`]
    /// handle for each. Handles are returned newest-first (Secret Manager's
    /// default ordering). Values are fetched lazily — no secret data is
    /// retrieved until [`get_secret_value`](huskarl_core::secrets::Secret::get_secret_value)
    /// is called on a handle.
    ///
    /// # Errors
    ///
    /// Returns an error if listing fails or no enabled versions are found.
    pub async fn get_secrets(&self) -> Result<Vec<SecretVersion<D>>, SecretVersionsError> {
        let versions = self.list_enabled_versions().await?;

        ensure!(!versions.is_empty(), NoEnabledSecretVersionsSnafu);

        Ok(versions
            .into_iter()
            .map(|v| {
                SecretVersion::builder()
                    .decoder(self.decoder.clone())
                    .client(self.client.clone())
                    .resource_name(v.name)
                    .build()
            })
            .collect())
    }

    /// Resolve the primary alias and list all enabled versions in a single
    /// consistent snapshot, returning both as [`ActiveSecretVersions`].
    ///
    /// Resolves the primary alias to a concrete version, lists all enabled
    /// versions, and confirms the primary is present. The returned
    /// [`ActiveSecretVersions::primary`] is guaranteed to be present in
    /// [`ActiveSecretVersions::all`], so there is no race between the
    /// encryption key and the set of decryptors.
    ///
    /// This is the typical factory body for a `ScheduledRefreshable`.
    ///
    /// # Errors
    ///
    /// Returns an error if resolving the primary alias fails, listing fails,
    /// no enabled versions are found, or the primary version is not among
    /// the enabled versions.
    pub async fn all(&self) -> Result<ActiveSecretVersions<D>, SecretVersionsError> {
        let primary_alias_resource =
            format!("{}/versions/{}", self.secret_name, self.primary_alias);

        // Resolve the alias and list all enabled versions concurrently.
        let (primary_meta, raw) = futures_util::try_join!(
            async {
                self.client
                    .get_secret_version()
                    .set_name(&primary_alias_resource)
                    .send()
                    .await
                    .context(GetSecretVersionSnafu)
            },
            self.list_enabled_versions(),
        )?;

        let primary_name = primary_meta.name;
        ensure!(!raw.is_empty(), NoEnabledSecretVersionsSnafu);

        // Build handles, tracking the primary by matching its resolved name.
        let mut primary_opt: Option<SecretVersion<D>> = None;
        let all: Vec<SecretVersion<D>> = raw
            .into_iter()
            .map(|v| {
                let handle = SecretVersion::builder()
                    .decoder(self.decoder.clone())
                    .client(self.client.clone())
                    .resource_name(v.name.clone())
                    .build();
                if v.name == primary_name {
                    primary_opt = Some(handle.clone());
                }
                handle
            })
            .collect();

        let primary = primary_opt.ok_or_else(|| PrimaryVersionNotFoundSnafu.build())?;

        Ok(ActiveSecretVersions { primary, all })
    }

    async fn list_enabled_versions(
        &self,
    ) -> Result<Vec<google_cloud_secretmanager_v1::model::SecretVersion>, SecretVersionsError> {
        let mut all_versions = Vec::new();
        let mut page_token = String::new();

        loop {
            let remaining = self
                .max_versions
                .map(|m| m.saturating_sub(all_versions.len()));
            if remaining == Some(0) {
                break;
            }

            let mut request = self
                .client
                .list_secret_versions()
                .set_parent(&self.secret_name)
                .set_filter("state=ENABLED");

            if let Some(n) = remaining {
                request = request.set_page_size(i32::try_from(n).unwrap_or(i32::MAX));
            }

            if !page_token.is_empty() {
                request = request.set_page_token(&page_token);
            }

            let response = request.send().await.context(ListSecretVersionsSnafu)?;

            all_versions.extend(response.versions);

            if response.next_page_token.is_empty()
                || self.max_versions.is_some_and(|m| all_versions.len() >= m)
            {
                break;
            }
            page_token = response.next_page_token;
        }

        Ok(all_versions)
    }
}
