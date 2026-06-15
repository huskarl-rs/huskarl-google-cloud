//! Google Cloud KMS crypto integrations.
//!
//! # Key rotation
//!
//! The key types here resolve a concrete `CryptoKeyVersion` **once, at build
//! time**, according to their [`VersionStrategy`], and then pin it: a built
//! [`SigningKey`](asymmetric::signer::SigningKey) or
//! [`CipherKey`](symmetric::cipher::CipherKey) keeps using that version no
//! matter what happens in KMS afterwards. They do not refresh themselves
//! (`try_refresh` is a no-op on them).
//!
//! To pick up a newly rotated version you **rebuild** the key. The
//! `huskarl-core` refresh wrappers do this for you: wrap the key in a
//! `ScheduledRefreshSigner` / `ScheduledRefreshCipher` (or the bare-mechanism
//! `RefreshableSigner` / `RefreshableCipher`) with a factory closure that
//! rebuilds it. On refresh the factory re-runs, re-resolves the version, and
//! the new key is swapped in atomically. A `RetryingDecryptor` /
//! `RetryingVerifier` layered on top will also trigger a refresh when it sees
//! a token or ciphertext whose key it does not yet hold.
//!
//! ## Rotating safely
//!
//! Decryption and verification keys load **all enabled versions**, so they
//! tolerate rotation as soon as they refresh. Signing and encryption keys pin
//! a **single** version, which makes the *choice* of [`VersionStrategy`]
//! load-bearing for encryption:
//!
//! - [`VersionStrategy::Latest`] starts encrypting with a brand-new version as
//!   soon as the encryptor reloads — which can outrun the decryptors on other
//!   servers and produce ciphertext they cannot yet read.
//! - [`VersionStrategy::ByLabel`] (promote a label only after every consumer
//!   has loaded the new version as a decryptor) or [`VersionStrategy::MinAge`]
//!   (skip versions younger than a propagation window) avoid that race.
//!
//! The order is: **add** the new version → **wait** for all consumers to load
//! it as a decryptor → **promote** it for encryption. Encryption should be the
//! last thing to switch.
//!
//! ## Example: a rotation-safe, self-refreshing AEAD cipher
//!
//! ```rust,no_run
//! use std::pin::Pin;
//!
//! use google_cloud_kms_v1::client::KeyManagementService;
//! use huskarl_core::crypto::cipher::ScheduledRefreshCipher;
//! use huskarl_core::platform::MaybeSendFuture;
//! use huskarl_core::{Error, ErrorKind};
//! use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::CipherKey};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let kms_client = KeyManagementService::builder().build().await?;
//! let key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k";
//!
//! // The factory rebuilds the key on every refresh, re-resolving the version.
//! let factory = move || -> Pin<Box<dyn MaybeSendFuture<Output = Result<CipherKey, Error>>>> {
//!     let kms_client = kms_client.clone();
//!     let key_name = key_name.to_owned();
//!     Box::pin(async move {
//!         CipherKey::builder()
//!             .key_name(key_name)
//!             .kms_client(kms_client)
//!             // Encrypt only with the label-pinned version, which you promote
//!             // *after* the new version has propagated to all decryptors.
//!             .strategy(VersionStrategy::ByLabel("active".into()))
//!             .build()
//!             .await
//!             .map_err(|e| Error::new(ErrorKind::Config, e))
//!     })
//! };
//!
//! // Refreshes are gated by a TTL (1 hour by default); decryption spans all
//! // enabled versions, so retired keys keep decrypting until disabled.
//! let cipher = ScheduledRefreshCipher::builder().factory(factory).build().await?;
//! # let _ = cipher;
//! # Ok(())
//! # }
//! ```
//!
//! The same shape works for signing: build a
//! [`SigningKey`](asymmetric::signer::SigningKey) in the factory and wrap it in
//! a `ScheduledRefreshSigner`.

pub mod asymmetric;
pub mod symmetric;
pub mod version;

pub use version::VersionStrategy;
