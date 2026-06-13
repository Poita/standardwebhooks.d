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

# Run all unit tests (core, including the official reference vectors).
test:
    ulimit -n 65536 && dub test

# Format the source in place (source/ + vibe/ + examples/, matching CI).
fmt:
    ulimit -n 65536 && dub run dfmt -- --inplace source/ vibe/ examples/

# Run the exact D-Scanner lint gate CI runs.
lint:
    ./scripts/dscanner-lint.sh

# Generate API documentation into docs/ (prefers adrdox).
docs:
    ./scripts/gen-docs.sh

# Build + run the runnable example (signs then verifies a payload).
example:
    ulimit -n 65536 && dub run --root examples/sign-verify
