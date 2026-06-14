# Common developer tasks for standardwebhooks.d.
#
# Run `just <task>` to invoke a recipe (install just from https://just.systems).
# Run `just` (or `just --list`) to see all available tasks.
#
# Every recipe sets `ulimit -n 65536` before invoking `dub`. Some terminals
# (notably ghostty) default to `ulimit -n unlimited`, under which the D
# toolchain spuriously hits its open-file limit and fails; an explicit, finite
# limit fixes it. See CONTRIBUTING.md ("The `ulimit -n` gotcha").

# Show the list of available recipes (default when you run bare `just`).
default:
    @just --list

# Build the core library.
build:
    ulimit -n 65536 && dub build

# Build the vibe.d integration subpackage.
build-vibe:
    ulimit -n 65536 && dub build :vibe

# Run the vibe.d integration subpackage unit tests.
test-vibe:
    ulimit -n 65536 && dub test :vibe

# Build the asymmetric ed25519 subpackage (requires system libsodium).
build-ed25519:
    ulimit -n 65536 && dub build :ed25519

# Run all unit tests (core, including the official reference vectors).
test:
    ulimit -n 65536 && dub test

# Run the asymmetric ed25519 subpackage unit tests (requires system libsodium).
test-ed25519:
    ulimit -n 65536 && dub test :ed25519

# Format the source in place (source/ + vibe/ + ed25519/ + examples/, matching CI).
fmt:
    ulimit -n 65536 && dub run dfmt -- --inplace source/ vibe/ ed25519/ examples/

# Run the exact D-Scanner lint gate CI runs.
lint:
    ./scripts/dscanner-lint.sh

# Generate API documentation into docs/ (prefers adrdox).
docs:
    ./scripts/gen-docs.sh

# Build + run the runnable examples (each signs then verifies a payload).
example:
    ulimit -n 65536 && dub run --root examples/sign-verify

# Build + run the asymmetric ed25519 example (requires system libsodium).
example-ed25519:
    ulimit -n 65536 && dub run --root examples/asymmetric
