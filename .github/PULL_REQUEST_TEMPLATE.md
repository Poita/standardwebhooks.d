## Summary

<!-- What does this PR change, and why? Reference the issue, e.g. "Closes #123". -->

Closes #

## Spec rule / behavior

<!-- The Standard Webhooks spec rule or reference-library behaviour this matches.
     Cite the spec section (standardwebhooks.com) or the reference test vector
     where relevant. -->

## Checklist

- [ ] **Tests added** — a failing test was written first (TDD), one case per `unittest` block.
- [ ] **`dub test` passes** — all modules green locally (`ulimit -n 65536 && dub test`).
- [ ] **`dfmt` clean** — ran `dub run dfmt -- --inplace source/ vibe/ examples/`; `git diff --exit-code` is clean.
- [ ] **`dscanner` clean** — ran `./scripts/dscanner-lint.sh`.
- [ ] **Core stays dependency-free** — no third-party imports added to `source/` (those belong in a subpackage).
- [ ] **Output unchanged vs. reference libraries** — signing/verification still matches the official vectors.
- [ ] **`CHANGELOG.md` updated** under `## [Unreleased]` if the change is user-visible.
