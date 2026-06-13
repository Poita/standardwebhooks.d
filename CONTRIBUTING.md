# Contributing to standardwebhooks.d

Thanks for your interest in improving this library. It aims to be a small,
correct, well-tested port of the [Standard Webhooks](https://www.standardwebhooks.com/)
specification — so contributions are held to the spec and the behaviour of the
official reference libraries.

## Ground rules

- **Match the spec and the reference libraries.** Any change to signing or
  verification must keep producing byte-for-byte the same output as the official
  Go/Python/JavaScript/Rust libraries. Cite the spec section or the reference
  test vector your change relies on.
- **Test-first.** Write a failing test before the fix, and put **one case per
  `unittest` block**. Port reference-library edge cases as named cases.
- **Keep the core dependency-free.** The root package uses Phobos only.
  Third-party dependencies belong in a subpackage (as `:vibe` does).
- **Format and lint.** `dub run dfmt -- --inplace source/ vibe/ examples/` and
  `./scripts/dscanner-lint.sh` must both be clean.

## Local workflow

```sh
just test          # or: ulimit -n 65536 && dub test
just build-vibe    # builds the vibe subpackage (fetches vibe-d)
just fmt
just lint
```

Open a PR against `main`. CI runs the formatter check, D-Scanner, and the test
matrix (ldc + dmd across Linux/macOS/Windows) plus the vibe subpackage build.

## The `ulimit -n` gotcha

Some terminals (notably ghostty) set `ulimit -n` to `unlimited`. Under an
unbounded descriptor limit the D toolchain can spuriously fail with open-file
errors. Set an explicit, finite limit before invoking `dub`:

```sh
ulimit -n 65536 && dub test
```

The `just` recipes already do this for you.

## Reporting security issues

Please do **not** open a public issue for vulnerabilities. See
[SECURITY.md](SECURITY.md).
