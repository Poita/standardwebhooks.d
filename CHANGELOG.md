# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Unit tests covering both official reference vectors and the reference
  libraries' edge cases (missing/malformed headers, tampered and multi
  signatures, tolerance boundaries, prefix/padding variants).

[Unreleased]: https://github.com/Poita/standardwebhooks.d/commits/main
