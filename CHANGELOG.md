# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Licensed under the MIT License (was Apache-2.0).

### Added

- Initial release: a faithful Standard Webhooks (standardwebhooks.com)
  implementation for D.
- `Webhook` value type with `sign`, `signHeaders`, `verify`, and
  `verifyIgnoringTimestamp`.
- Construction from a `whsec_`-prefixed or bare base64 secret (padded or
  unpadded), or from raw key bytes via `Webhook.fromRaw`.
- HMAC-SHA256 / `v1` signatures, standard-base64 encoded; multi-signature
  headers for secret rotation; constant-time comparison.
- Timestamp replay protection with a configurable tolerance window
  (`toleranceSeconds`, default ±5 minutes).
- Case-insensitive header lookup with Svix-branded (`svix-*`) header fallback.
- `WebhookVerificationException` carrying a machine-readable `WebhookError`
  cause.
- Optional `standardwebhooks:vibe` subpackage: `verifyRequest` and `signRequest`
  helpers for vibe.d HTTP.
- Optional `standardwebhooks:ed25519` subpackage: the spec's asymmetric `v1a`
  scheme via libsodium. `AsymmetricWebhook` constructs from a `whsk_` signing key
  or `whpk_` public key (or `fromSeed`), mirroring the `Webhook` API with
  `sign`/`signHeaders`/`verify`/`verifyIgnoringTimestamp`, `publicKeyEncoded`,
  `signingKeyEncoded`, and `canSign`. Verified against the Svix server's
  `v1a` golden vector.
- `WebhookError.signingKeyRequired`, thrown when signing with a verify-only
  (`whpk_`) asymmetric key.
- Unit tests covering both official reference vectors and the reference
  libraries' edge cases (missing/malformed headers, tampered and multi
  signatures, tolerance boundaries, prefix/padding variants).

[Unreleased]: https://github.com/Poita/standardwebhooks.d/commits/main
