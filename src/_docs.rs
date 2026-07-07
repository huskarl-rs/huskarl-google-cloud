//! Extended documentation: how-to guides and explanation.
//!
//! The API items in this crate are the **reference** documentation — they say
//! what each type and method is. These pages cover the other
//! [Diátaxis](https://diataxis.fr) quadrants:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for signing, encrypting,
//!   serving public keys, refreshing keys under rotation, and reading secrets.
//! - **[Explanation](explanation)** — understanding-oriented background on the
//!   version and rotation model, key IDs, and error handling.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(any(doc, docsrs))`, so it renders under `cargo doc` and its code
//! blocks are real doctests that run under `RUSTDOCFLAGS="--cfg docsrs"
//! cargo +nightly test --doc` (mirroring the docs.rs build environment, which
//! the `[package.metadata.docs.rs]` block configures); a plain
//! `cargo test --doc` skips them.

/// Task-oriented recipes for signing, encrypting, and reading secrets.
pub mod guide {
    #[doc = include_str!("../docs/guide/asymmetric_signing.md")]
    pub mod asymmetric_signing {}

    #[doc = include_str!("../docs/guide/symmetric_crypto.md")]
    pub mod symmetric_crypto {}

    #[doc = include_str!("../docs/guide/refreshing_keys.md")]
    pub mod refreshing_keys {}

    #[doc = include_str!("../docs/guide/secret_manager.md")]
    pub mod secret_manager {}
}

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/versions_and_rotation.md")]
    pub mod versions_and_rotation {}

    #[doc = include_str!("../docs/explanation/key_ids.md")]
    pub mod key_ids {}

    #[doc = include_str!("../docs/explanation/error_handling.md")]
    pub mod error_handling {}
}
