//! Google Cloud Secret Manager integration for retrieving secrets.

use bon::Builder;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::platform::MaybeSendBoxFuture;
use huskarl_core::secrets::encodings::StringEncoding;
use huskarl_core::secrets::{MappedSecret, Secret, SecretBytes, SecretMap, SecretOutput};
use snafu::prelude::*;

use crate::kid::VersionKid;

pub use versions::ActiveSecretVersions;
pub use versions::SecretVersions;
pub use versions::SecretVersionsError;

mod versions;

/// Errors that can occur when using the Google Cloud Secret Manager API.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretError {
    /// Failed to access the secret value data.
    AccessSecret {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// The secret response did not contain a payload.
    ///
    /// This may happen if the secret is disabled or destroyed.
    MissingPayload,
}

impl SecretError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::AccessSecret { source } => source.is_exhausted() || source.is_timeout(),
            Self::MissingPayload => false,
        }
    }
}

impl From<SecretError> for huskarl_core::Error {
    fn from(err: SecretError) -> Self {
        let kind = if err.is_retryable() {
            huskarl_core::ErrorKind::Transport { retryable: true }
        } else {
            huskarl_core::ErrorKind::Config
        };
        huskarl_core::Error::new(kind, err)
    }
}

/// A specific version in Google Cloud Secret Manager, as raw bytes.
///
/// This is the byte source: `Secret<Output = SecretBytes>`. Fetch with
/// [`get_secret_value`](Secret::get_secret_value) and read the material via
/// [`expose_secret`](SecretBytes::expose_secret) — this is the raw path, and no
/// decoding is applied. To view the value as UTF-8 text or decode base64/hex,
/// wrap it in [`SecretVersion`] or compose a [`SecretMap`] with
/// [`Secret::mapped`].
///
/// The `resource_name` should be the fully-qualified secret version resource
/// name, e.g. `projects/p/secrets/s/versions/3`. The built-in `latest` alias
/// (`projects/p/secrets/s/versions/latest`) and any custom aliases are also
/// accepted.
///
/// # Usage
///
/// ```rust
/// # use huskarl_google_cloud::secretmanager::SecretVersionBytes;
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
/// # async fn setup(secret_manager: SecretManagerService) {
///     let bytes = SecretVersionBytes::builder()
///         .client(secret_manager)
///         .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///         .build();
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretVersionBytes {
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret version resource name (e.g. "projects/x/secrets/y/versions/z").
    #[builder(into)]
    resource_name: String,
    /// How to derive the fetched value's `identity` (and thus its `kid`) from
    /// the secret version. Defaults to [`VersionKid::verbatim()`] — the version
    /// segment is used as-is.
    #[builder(default = VersionKid::verbatim())]
    kid: VersionKid,
}

impl SecretVersionBytes {
    /// The fully-qualified secret version resource name this source fetches.
    #[must_use]
    pub fn resource_name(&self) -> &str {
        &self.resource_name
    }
}

impl Secret for SecretVersionBytes {
    type Output = SecretBytes;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, huskarl_core::Error>> {
        Box::pin(async move {
            let response = self
                .client
                .access_secret_version()
                .set_name(&self.resource_name)
                .send()
                .await
                .context(AccessSecretSnafu)?;

            let payload = response.payload.context(MissingPayloadSnafu)?;

            Ok(SecretOutput {
                value: SecretBytes::new(payload.data.to_vec()),
                identity: response
                    .name
                    .rsplit('/')
                    .next()
                    .and_then(|version| self.kid.derive(version)),
            })
        })
    }
}

/// A [`SecretVersionBytes`] decoded through a [`SecretMap`] (UTF-8 text by
/// default).
///
/// A pre-composed [`SecretVersionBytes`] + [`MappedSecret`]: it fetches the
/// version on every access and maps the bytes with `M`, defaulting to
/// [`StringEncoding`] so the output is a
/// [`SecretString`](huskarl_core::secrets::SecretString). The source's identity
/// (the trailing version segment) is passed through unchanged. For raw bytes,
/// use [`SecretVersionBytes`] directly; for an ad-hoc map at a call site, prefer
/// [`Secret::mapped`] on a [`SecretVersionBytes`].
///
/// # Usage
///
/// ```rust
/// # use huskarl_google_cloud::secretmanager::{SecretVersion, SecretVersionBytes};
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
/// # async fn setup(secret_manager: SecretManagerService) {
///     let text = SecretVersion::string(
///         SecretVersionBytes::builder()
///             .client(secret_manager)
///             .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///             .build(),
///     );
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SecretVersion<M: SecretMap<In = SecretBytes> = StringEncoding> {
    inner: MappedSecret<SecretVersionBytes, M>,
}

impl<M: SecretMap<In = SecretBytes>> SecretVersion<M> {
    /// Wraps a byte source, decoding each fetch through `map`.
    #[must_use]
    pub fn new(source: SecretVersionBytes, map: M) -> Self {
        let context = format!("decoding secret version {}", source.resource_name());
        Self {
            inner: MappedSecret::new(source, map).with_context(context),
        }
    }
}

impl SecretVersion {
    /// Decodes each fetch as UTF-8 text via [`StringEncoding`].
    #[must_use]
    pub fn string(source: SecretVersionBytes) -> Self {
        Self::new(source, StringEncoding)
    }
}

impl<M: SecretMap<In = SecretBytes>> Secret for SecretVersion<M> {
    type Output = M::Out;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, huskarl_core::Error>> {
        self.inner.get_secret_value()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::future::Future;

    use google_cloud_gax::Result as GaxResult;
    use google_cloud_gax::options::RequestOptions;
    use google_cloud_gax::response::Response;
    use google_cloud_secretmanager_v1::model::{
        AccessSecretVersionRequest, AccessSecretVersionResponse, SecretPayload,
    };
    use google_cloud_secretmanager_v1::stub::SecretManagerService as SmStub;
    use huskarl_core::ErrorKind;
    use rstest::rstest;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct MockSm {
        response_name: String,
        /// `None` simulates a disabled/destroyed version with no payload.
        data: Option<Vec<u8>>,
    }

    impl SmStub for MockSm {
        fn access_secret_version(
            &self,
            _req: AccessSecretVersionRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<AccessSecretVersionResponse>>> + Send {
            let mut resp =
                AccessSecretVersionResponse::default().set_name(self.response_name.clone());
            if let Some(data) = self.data.clone() {
                resp = resp.set_payload(SecretPayload::default().set_data(data));
            }
            async move { Ok(Response::from(resp)) }
        }
    }

    fn secret_version_bytes(mock: MockSm) -> SecretVersionBytes {
        SecretVersionBytes::builder()
            .client(SecretManagerService::from_stub(mock))
            .resource_name("projects/p/secrets/s/versions/3")
            .build()
    }

    #[rstest]
    #[case(SecretError::MissingPayload)]
    fn secret_error_classifies_as_config(#[case] err: SecretError) {
        assert!(!err.is_retryable());
        assert_eq!(huskarl_core::Error::from(err).kind(), ErrorKind::Config);
    }

    #[tokio::test]
    async fn bytes_source_returns_raw_data_and_identity() {
        let sv = secret_version_bytes(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"  hunter2  ".to_vec()),
        });

        let out = sv.get_secret_value().await.unwrap();
        // The byte source is verbatim — no trimming, no decoding.
        assert_eq!(out.value.expose_secret(), b"  hunter2  ");
        // Identity is the trailing version segment of the resolved name.
        assert_eq!(out.identity.as_deref(), Some("7"));
    }

    #[tokio::test]
    async fn kid_policy_transforms_or_suppresses_the_identity() {
        let mock = MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"x".to_vec()),
        };

        // `map` transforms the version into the identity/kid (a capability the
        // Secret Manager side gained from the shared `VersionKid`).
        let mapped = SecretVersionBytes::builder()
            .client(SecretManagerService::from_stub(mock.clone()))
            .resource_name("projects/p/secrets/s/versions/3")
            .kid(VersionKid::map(|v| format!("sm-key-{v}")))
            .build();
        assert_eq!(
            mapped.get_secret_value().await.unwrap().identity.as_deref(),
            Some("sm-key-7"),
        );

        // `none` suppresses the identity entirely.
        let none = SecretVersionBytes::builder()
            .client(SecretManagerService::from_stub(mock))
            .resource_name("projects/p/secrets/s/versions/3")
            .kid(VersionKid::none())
            .build();
        assert_eq!(none.get_secret_value().await.unwrap().identity, None);
    }

    #[tokio::test]
    async fn string_wrapper_decodes_and_extracts_identity() {
        let sv = SecretVersion::string(secret_version_bytes(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"  hunter2  ".to_vec()), // surrounding whitespace is trimmed
        }));

        let out = sv.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), "hunter2");
        // Identity passes through the map unchanged.
        assert_eq!(out.identity.as_deref(), Some("7"));
    }

    #[tokio::test]
    async fn get_secret_value_reports_missing_payload_as_config() {
        let sv = secret_version_bytes(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: None,
        });

        let err = sv.get_secret_value().await.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Config);
    }
}
