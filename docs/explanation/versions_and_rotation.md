# Key versions and rotation

Cloud KMS keys and Secret Manager secrets are *versioned*: a `CryptoKey` (or a
secret) is a stable name under which individual versions come and go. This crate
turns those versions into `huskarl` signers, verifiers, and ciphers, and the
rules below govern which version a given construct uses — the single most
important thing to understand before deploying under rotation.

## Versions are resolved once, then pinned

Every key type here resolves its version(s) **at build time** and then pins the
result. A built
[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) or
[`CipherKey`](crate::kms::symmetric::cipher::CipherKey) keeps using exactly the
version(s) it resolved, no matter what happens in KMS afterwards. They do not
poll or refresh themselves — `try_refresh` is a no-op.

To pick up a newly rotated version you **rebuild** the key. You rarely do this
by hand: the `huskarl-core` refresh wrappers rebuild on a schedule for you — see
the [self-refreshing keys guide](crate::_docs::guide::refreshing_keys).

## One version to write, all versions to read

The asymmetry that makes rotation safe:

- **Signing and encryption pin a single version.** A signer emits one
  signature; an encryptor emits one ciphertext. There is exactly one *current*
  version, chosen by the [`VersionStrategy`](crate::kms::VersionStrategy).
- **Verification and decryption span every enabled version.** A verifier must
  accept signatures made by any not-yet-retired key; a decryptor must read
  ciphertext produced by any of them. So these load *all* enabled versions and
  route by `kid`/algorithm (see [key IDs](crate::_docs::explanation::key_ids)).

[`CipherKey`](crate::kms::symmetric::cipher::CipherKey) and the HMAC
[`VerifyingKey`](crate::kms::symmetric::signer::VerifyingKey) /
[`SigningKey`](crate::kms::symmetric::signer::SigningKey) pairing combine both
sides: encrypt/sign with one, decrypt/verify with all.

## Why the strategy is load-bearing for encryption

Because reading tolerates any enabled version but writing commits to one, the
*choice* of which version to write with is where rotation races live. That
choice is the [`VersionStrategy`](crate::kms::VersionStrategy):

- [`Latest`](crate::kms::VersionStrategy::Latest) starts writing with a
  brand-new version the moment an encryptor reloads. If other servers haven't
  yet loaded that version as a *decryptor*, they receive ciphertext they cannot
  read. Fine for signing (verifiers span all enabled versions, so a new signing
  version is readable as soon as it exists); risky for encryption.
- [`ByLabel`](crate::kms::VersionStrategy::ByLabel) writes with whichever
  version a label on the `CryptoKey` points at. You promote the label only
  *after* every consumer has loaded the new version as a decryptor — so the
  encryptor can never outrun the decryptors.
- [`MinAge`](crate::kms::VersionStrategy::MinAge) writes with the newest version
  that is at least a given age old, skipping versions younger than your
  propagation window. A coarser, time-based alternative to `ByLabel`.
- [`Specific`](crate::kms::VersionStrategy::Specific) pins a version ID
  outright — no automatic movement at all.

## The safe rotation order

For encryption keys the ordering is always:

1. **Add** the new version.
2. **Wait** for every consumer to load it as a decryptor (they will on their
   next refresh).
3. **Promote** it for encryption — flip the `ByLabel` label, or let `MinAge`
   age it in.

Encryption should be the *last* thing to switch. Signing has no such
constraint: verifiers accept the new version as soon as it is enabled, so
`Latest` is a fine default there.

## Secret Manager follows the same shape

Multi-version secrets work the same way.
[`SecretVersions`](crate::secretmanager::SecretVersions) exposes a **primary**
version (resolved through a caller-controlled alias, the Secret Manager
equivalent of `ByLabel`) and **all** enabled versions together, as a consistent
snapshot in which the primary is guaranteed to appear among the enabled set.
Write with the primary; build a decryptor from all. Promote by repointing the
alias — again, only after every consumer has the new version. See the
[Secret Manager guide](crate::_docs::guide::secret_manager).
