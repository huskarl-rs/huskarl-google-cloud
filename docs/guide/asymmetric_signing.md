# Signing JWS and serving JWKS with an asymmetric KMS key

An asymmetric Cloud KMS `CryptoKey` (an EC, RSA, or Ed25519 signing key) gives
you two halves of a JWS setup: a private signer that stays inside KMS, and the
public keys you publish so others can verify. This crate provides
[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) for the first and
[`Jwks`](crate::kms::asymmetric::jwks::Jwks) for the second.

## Sign with the current version

[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) resolves a primary
version via its [`VersionStrategy`](crate::kms::VersionStrategy) (defaulting to
[`Latest`](crate::kms::VersionStrategy::Latest)) and signs with it. It also
loads every other enabled version so it can select a signer by JWK thumbprint.
It implements [`JwsSignerSelector`](huskarl_core::crypto::signer::JwsSignerSelector),
so hand it to any `huskarl` construct that signs — or drive it directly:

```rust,no_run
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::crypto::signer::JwsSignerSelector;
use huskarl_google_cloud::kms::asymmetric::signer::SigningKey;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;

let key = SigningKey::builder()
    .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
    .kms_client(kms_client)
    .build()
    .await?;

// Select the signer for the primary version and sign the JWS signing input.
let signer = key.select_signer().await;
let signature = signer.sign(b"protected.payload").await?;
# let _ = signature;
# Ok(())
# }
```

The algorithm is discovered from the key: EC P-256/P-384 become `ES256`/`ES384`
(and KMS's DER signatures are converted to the fixed-width `r‖s` JWS form for
you), RSA becomes `RS*`/`PS*`, and Ed25519 becomes `Ed25519` — or the
deprecated `EdDSA` identifier if you set `use_fully_specified_jws_algorithm` to
`false`.

## Serve the public keys as a JWKS

[`Jwks`](crate::kms::asymmetric::jwks::Jwks) fetches the public keys of every
enabled version as a [`PublicJwks`](huskarl_core::jwk::PublicJwks) — the
document a resource server or verifier consumes. It caches nothing; call
[`fetch`](crate::kms::asymmetric::jwks::Jwks::fetch) behind your own caching
(for example a `RefreshingVerifier`), and set a
[`kid`](crate::kid::VersionKid) so verifiers can select a key by ID:

```rust,no_run
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_google_cloud::kid::VersionKid;
use huskarl_google_cloud::kms::asymmetric::jwks::Jwks;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;

let jwks = Jwks::builder()
    .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
    .kms_client(kms_client)
    // Give each published key a stable `kid`; verifiers match it against the
    // JWS header. See the key-IDs explanation for the choices.
    .kid(VersionKid::map(|version| format!("kms-v{version}")))
    .build();

let public_jwks = jwks.fetch().await?;
# let _ = public_jwks;
# Ok(())
# }
```

Because verifiers accept any enabled version, a signing key rotates safely under
the default `Latest` strategy — a new version is verifiable the moment it is
enabled and its public key appears in the JWKS. See
[key versions and rotation](crate::_docs::explanation::versions_and_rotation),
[key IDs](crate::_docs::explanation::key_ids), and — to refresh the signer and
JWKS automatically — the
[self-refreshing keys guide](crate::_docs::guide::refreshing_keys).

> **Bounding the fetch.** Both builders take `max_versions`. When set, at most
> that many enabled versions are loaded (newest-first) in a single API call;
> when unset, all enabled versions are fetched, paging as needed.
