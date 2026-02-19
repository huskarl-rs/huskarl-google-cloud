//! Google Cloud Secret Manager integration for retrieving secrets.

use bon::Builder;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::secrets::{DecodingError, Secret, SecretDecoder, SecretOutput};
use snafu::prelude::*;

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
        source: DecodingError,
    },
}

impl huskarl_core::Error for SecretError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::AccessSecret { source } => source.is_exhausted() || source.is_timeout(),
            Self::MissingPayload | Self::Decode { .. } => false,
        }
    }
}

/// A secret value stored in Google Cloud Secret Manager.
///
/// # Usage
///
/// ```rust
/// # use huskarl_core::secrets::encodings::StringEncoding;
/// # use huskarl_google_cloud::secretmanager::SecretManagerSecret;
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
///
/// # async fn setup(secret_manager: SecretManagerService) {
///   let secret = SecretManagerSecret::builder()
///   .decoder(StringEncoding)
///   .client(secret_manager)
///   .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///   .build();
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretManagerSecret<D: SecretDecoder> {
    /// The decoder applied to the secret data.
    decoder: D,
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret resource name (e.g. "projects/x/secrets/y/versions/z").
    #[builder(into)]
    resource_name: String,
}

impl<D: SecretDecoder> Secret for SecretManagerSecret<D> {
    type Error = SecretError;
    type Output = D::Output;

    async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
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
    }
}
