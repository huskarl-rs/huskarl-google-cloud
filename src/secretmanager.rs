//! Google Cloud Secret Manager integration for retrieving secrets.

use bon::Builder;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::platform::MaybeSendBoxFuture;
use huskarl_core::secrets::{Secret, SecretDecoder, SecretOutput};
use snafu::prelude::*;

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
    /// Failed to decode the secret data.
    Decode {
        /// The encoding error
        source: huskarl_core::Error,
    },
}

impl SecretError {
    /// If true, the failure is transient and the operation may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::AccessSecret { source } => source.is_exhausted() || source.is_timeout(),
            Self::MissingPayload | Self::Decode { .. } => false,
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

/// A secret pinned to a specific version in Google Cloud Secret Manager.
///
/// The `resource_name` should be the fully-qualified secret version resource
/// name, e.g. `projects/p/secrets/s/versions/3`. The built-in `latest` alias
/// (`projects/p/secrets/s/versions/latest`) and any custom aliases are also
/// accepted.
///
/// # Usage
///
/// ```rust
/// # use huskarl_core::secrets::encodings::StringEncoding;
/// # use huskarl_google_cloud::secretmanager::SecretVersion;
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
///
/// # async fn setup(secret_manager: SecretManagerService) {
///     let secret = SecretVersion::builder()
///         .decoder(StringEncoding)
///         .client(secret_manager)
///         .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///         .build();
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretVersion<D: SecretDecoder> {
    /// The decoder applied to the secret data.
    decoder: D,
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret version resource name (e.g. "projects/x/secrets/y/versions/z").
    #[builder(into)]
    resource_name: String,
}

impl<D: SecretDecoder> Secret for SecretVersion<D> {
    type Output = D::Output;

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
            let secret_value = self.decoder.decode(&payload.data).context(DecodeSnafu)?;

            Ok(SecretOutput {
                value: secret_value,
                identity: response.name.rsplit('/').next().map(String::from),
            })
        })
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
    use huskarl_core::secrets::encodings::StringEncoding;
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

    fn secret_version(mock: MockSm) -> SecretVersion<StringEncoding> {
        SecretVersion::builder()
            .decoder(StringEncoding)
            .client(SecretManagerService::from_stub(mock))
            .resource_name("projects/p/secrets/s/versions/3")
            .build()
    }

    #[rstest]
    #[case(SecretError::MissingPayload)]
    #[case(SecretError::Decode { source: ErrorKind::Config.into() })]
    fn secret_error_classifies_as_config(#[case] err: SecretError) {
        assert!(!err.is_retryable());
        assert_eq!(huskarl_core::Error::from(err).kind(), ErrorKind::Config);
    }

    #[tokio::test]
    async fn get_secret_value_decodes_and_extracts_identity() {
        let sv = secret_version(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"  hunter2  ".to_vec()), // surrounding whitespace is trimmed
        });

        let out = sv.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), "hunter2");
        // Identity is the trailing version segment of the resolved name.
        assert_eq!(out.identity.as_deref(), Some("7"));
    }

    #[tokio::test]
    async fn get_secret_value_reports_missing_payload_as_config() {
        let sv = secret_version(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: None,
        });

        let err = sv.get_secret_value().await.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Config);
    }
}
