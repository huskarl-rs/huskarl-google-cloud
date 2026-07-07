# Error handling

The crate's errors fall into two families, split by *where* they surface: the
one-time setup path where you build a key, and the runtime path where a built
key runs through a `huskarl` trait method.

## Setup errors

Building a key or fetching versions returns a crate-specific error you handle at
the call site:

- KMS: [`asymmetric::signer::SetupError`](crate::kms::asymmetric::signer::SetupError),
  [`asymmetric::jwks::JwksError`](crate::kms::asymmetric::jwks::JwksError),
  [`kms::SetupError`](crate::kms::symmetric::SetupError) and
  [`kms::KeyError`](crate::kms::symmetric::KeyError) (shared by the symmetric
  builders), and the underlying
  [`VersionResolutionError`](crate::kms::version::VersionResolutionError).
- Secret Manager:
  [`SecretVersionsError`](crate::secretmanager::SecretVersionsError).

These carry the failure detail (which API call failed, an unsupported
algorithm, no enabled versions) and are `#[non_exhaustive]`. Most expose an
[`is_retryable()`](crate::kms::symmetric::KeyError::is_retryable) predicate —
`true` for transient conditions (request timeout, resource exhausted), `false`
for structural ones (unsupported algorithm, no enabled versions, a label that
resolves to nothing). Use it to decide whether to back off and retry the build,
or fail fast.

Setup errors are **not** auto-converted to
[`huskarl_core::Error`](huskarl_core::Error). Inside a refresh factory (see the
[self-refreshing keys guide](crate::_docs::guide::refreshing_keys)) map them
yourself — typically to [`ErrorKind::Config`](huskarl_core::ErrorKind::Config):

```rust,no_run
use huskarl_core::{Error, ErrorKind};
use huskarl_google_cloud::kms::symmetric::cipher::CipherKey;

# async fn example(builder_result: Result<CipherKey, huskarl_google_cloud::kms::symmetric::KeyError>) -> Result<CipherKey, Error> {
builder_result.map_err(|e| Error::new(ErrorKind::Config, e))
# }
```

## Runtime errors

Once built, a key runs through a `huskarl` trait method — `sign`, `verify`,
`encrypt`, `decrypt`, or `get_secret_value` — and those return
[`huskarl_core::Error`](huskarl_core::Error) directly. The per-operation error
types implement `From<_> for huskarl_core::Error`, mapping their retryability
onto an [`ErrorKind`](huskarl_core::ErrorKind):

- [`Transport { retryable: true }`](huskarl_core::ErrorKind::Transport) for
  transient KMS/Secret Manager failures (timeout, exhausted).
- [`Crypto`](huskarl_core::ErrorKind::Crypto) for conclusive crypto failures —
  a signature that would not convert, a mismatched response.
- [`Config`](huskarl_core::ErrorKind::Config) for a missing secret payload.

The types involved are
[`asymmetric::signer::SigningError`](crate::kms::asymmetric::signer::SigningError),
[`symmetric::cipher::EncryptionError`](crate::kms::symmetric::cipher::EncryptionError)
/ [`DecryptionError`](crate::kms::symmetric::cipher::DecryptionError),
[`symmetric::signer::SigningError`](crate::kms::symmetric::signer::SigningError)
/ [`VerificationError`](crate::kms::symmetric::signer::VerificationError), and
[`SecretError`](crate::secretmanager::SecretError). You normally never name them
— you get a `huskarl_core::Error` and match on its
[`kind()`](huskarl_core::Error::kind).

## `MismatchedKeyInfo` means rotation happened under you

A signing or encryption call whose response comes back bound to a *different*
version than requested yields a `MismatchedKeyInfo` error (mapped to
[`Crypto`](huskarl_core::ErrorKind::Crypto), non-retryable). It means the pinned
version was replaced in KMS while the key was live. The fix is not to retry the
same call but to **rebuild** the key against the new version — exactly what the
refresh wrappers do on their next cycle. See
[key versions and rotation](crate::_docs::explanation::versions_and_rotation).
