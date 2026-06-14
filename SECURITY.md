# Security Policy

This library implements signature verification for webhooks, so correctness here
is a security boundary. Reports of vulnerabilities are taken seriously.

## Reporting a vulnerability

Please report security issues **privately**, not as a public GitHub issue:

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab), or
- email the maintainer at the address on their GitHub profile.

Please include a description, affected versions, and a minimal reproduction if
possible. You can expect an acknowledgement within a few days.

## Scope

Security-relevant concerns for this library include, for example:

- A forged or tampered payload that `verify` accepts.
- A timing side channel in signature comparison.
- A replay outside the configured tolerance window that is accepted.
- Incorrect secret decoding that weakens the HMAC key.

## What this library guarantees

- Signatures are compared in constant time (no early-exit on the first differing
  byte beyond the length check that every reference library performs).
- The exact received bytes are what get verified — verify the raw body before
  parsing or re-serializing it.
- Timestamps outside `toleranceSeconds` (±5 minutes by default) are rejected.

It does **not** manage secret storage, rotation policy, or transport security
(use TLS); those are the integrating application's responsibility.

## Dependency constraints

The optional `standardwebhooks:vibe` subpackage pins `vibe-d:http` to the
`0.10.x` line. The earlier `0.9.x` line is unmaintained and shares the HTTP
request-smuggling exposure tracked in GHSA-hm69-r6ch-92wx, so the constraint was
moved across the minor boundary deliberately. dub's `~>` operator never crosses a
minor version, so picking up vibe.d HTTP framing fixes like this one requires a
manual bump of the constraint rather than a plain `dub upgrade`.
