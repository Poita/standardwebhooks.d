# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `WebhookError.cryptoFailure`, reported when an ed25519/libsodium primitive or
  initialisation fails, distinct from caller-input error codes.
- Tests for the vibe subpackage helpers and the real-clock `verify()` path of
  the asymmetric scheme; the signature-entry cap is now pinned by a test.
- Documentation of the signature-entry cap, the `toleranceSeconds` contract,
  the asymmetric throwing contracts, and Windows/libsodium setup.

### Changed

- `lookupHeader` now prefers the canonical header over its `svix-*` alias
  deterministically when both are present, instead of depending on map
  iteration order.
- libsodium's one-time initialisation guard uses acquire/release atomics.
- Asymmetric `v1a` signatures must be canonical padded base64, matching `v1`
  and the specification.

### Fixed

- The vibe.d `verifyRequest` helper reads the raw request body and verifies the
  exact bytes received, so payloads survive verification unchanged.
- `verifyTimestamp` guards against extreme or overflowing timestamp values
  rather than wrapping the tolerance arithmetic, and reports a non-UTF-8
  timestamp header as invalid headers instead of an unhandled exception.
- The signature header parser caps the number of `v1` entries it examines,
  bounding work on adversarially large headers.
- `AsymmetricWebhook.fromSeed` returns the constructed value as documented.
- Crypto and library failures report `WebhookError.cryptoFailure` instead of
  unrelated caller-input error codes.
- Coverage is measured per target in CI so shared `.lst` files no longer
  clobber one another, and the test suite compiles under
  `-preview=dip1000 -preview=in`.

### Security

- libsodium is initialised lazily on first asymmetric use, keeping the
  dependency-free core free of load-time side effects.
- Malformed base64 in an attacker-controlled signature (or a corrupt secret) is
  rejected cleanly instead of aborting the process through an uncatchable error.
- The vibe.d integration depends on `vibe-d:http` 0.10.x, moving off a frozen
  0.9.x release that overlaps an HTTP request-smuggling advisory
  (GHSA-hm69-r6ch-92wx); HTTP-framing fixes require a manual constraint bump
  because dub `~>` will not cross the minor boundary.
- The asymmetric subpackage rejects a libsodium too old to provide the detached
  ed25519 API it calls.

## [0.1.0] - 2026-06-14

### Added

- Initial release: a faithful Standard Webhooks (standardwebhooks.com)
  implementation for D, licensed under the MIT License.
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

[Unreleased]: https://github.com/Poita/standardwebhooks.d/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Poita/standardwebhooks.d/releases/tag/v0.1.0
