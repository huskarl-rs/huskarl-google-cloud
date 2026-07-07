<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Google Cloud Platform crypto integrations for `huskarl`.

- [`kms`](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/kms/) — Cloud KMS signers, verifiers, and AEAD ciphers (asymmetric JWS,
  symmetric HMAC and AES), with version pinning and rotation support.
- [`secretmanager`](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/secretmanager/) — a `huskarl` secret provider backed by Secret Manager.

Each lives behind a cargo feature of the same name.

# Guides and explanation

The API items here are the **reference** documentation. For task-oriented
how-to guides — [signing JWS and serving a
JWKS](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/asymmetric_signing/), [symmetric encryption and
HMAC](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/symmetric_crypto/), [refreshing keys under
rotation](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/refreshing_keys/), and [reading
secrets](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/guide/secret_manager/) — and design explanation ([key
versions and rotation](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/explanation/versions_and_rotation/), [key
IDs](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/explanation/key_ids/), [error
handling](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/explanation/error_handling/)), see the [`_docs`](https://docs.rs/huskarl-google-cloud/latest/huskarl_google_cloud/_docs/) module.

<!-- cargo-reedme: end -->
