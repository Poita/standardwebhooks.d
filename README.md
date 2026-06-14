# standardwebhooks.d

[![CI](https://github.com/Poita/standardwebhooks.d/actions/workflows/ci.yml/badge.svg)](https://github.com/Poita/standardwebhooks.d/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Poita/standardwebhooks.d/branch/main/graph/badge.svg)](https://codecov.io/gh/Poita/standardwebhooks.d)
[![Dub version](https://img.shields.io/dub/v/standardwebhooks.svg)](https://code.dlang.org/packages/standardwebhooks)
[![Dub downloads](https://img.shields.io/dub/dt/standardwebhooks.svg)](https://code.dlang.org/packages/standardwebhooks)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![API docs](https://img.shields.io/badge/docs-API%20reference-blue.svg)](https://poita.github.io/standardwebhooks.d/)

A faithful [Standard Webhooks](https://www.standardwebhooks.com/) implementation
for the D programming language — sign outgoing webhooks and verify incoming ones
with HMAC-SHA256, constant-time comparison, and timestamp replay protection.

The core is **dependency-free** (Phobos only). Two optional subpackages extend
it: [`standardwebhooks:vibe`](#vibed-integration) wires it directly into
[vibe.d](https://vibed.org) HTTP requests, and
[`standardwebhooks:ed25519`](#asymmetric-ed25519-signatures) adds the spec's
asymmetric `v1a` signatures via libsodium.

## Why Standard Webhooks?

[Standard Webhooks](https://www.standardwebhooks.com/) is an open specification
for securing webhooks, backed by a set of reference libraries across languages.
A sender signs the message id, timestamp, and raw body; a receiver recomputes
the signature and rejects anything that does not match or is too old. This
library produces and accepts byte-for-byte the same `webhook-signature` values
as the official Go, Python, JavaScript, and Rust libraries (verified against
their published test vectors).

## Install

```sh
dub add standardwebhooks
```

or in `dub.json`:

```json
"dependencies": {
    "standardwebhooks": "~>0.1"
}
```

## Quickstart

```d
import standardwebhooks;

void main()
{
    // The secret you share with the other side. The `whsec_` prefix is
    // optional; raw key bytes are also supported via Webhook.fromRaw.
    auto wh = Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

    string id = "msg_2b3c4d5e";
    long timestamp = 1614265330;          // unix seconds
    string payload = `{"event":"ping"}`;  // the raw request body

    // --- Sending: build the three headers to attach to your HTTP request ---
    string[string] headers = wh.signHeaders(id, timestamp, payload);
    // headers["webhook-id"], ["webhook-timestamp"], ["webhook-signature"]

    // --- Receiving: verify an incoming request (throws on any mismatch) ---
    auto verified = wh.verify(payload, headers);
    assert(verified == payload);
}
```

`verify` throws a
[`WebhookVerificationException`](https://poita.github.io/standardwebhooks.d/)
if a header is missing, the timestamp is outside the tolerance window (±5
minutes by default), or no signature matches. On success it returns the raw
payload so you can parse it in the same expression:

```d
import std.json : parseJSON;

try
{
    auto data = parseJSON(wh.verify(body_, request.headers));
    handleEvent(data);
}
catch (WebhookVerificationException e)
{
    // Reject with HTTP 400; e.error gives the machine-readable cause.
}
```

## API

All of the following live on the `Webhook` value type.

| Member | Purpose |
| --- | --- |
| `Webhook(string secret)` | Construct from a `whsec_`-prefixed or bare base64 secret. Padded or unpadded base64 both work. |
| `Webhook.fromRaw(ubyte[] key)` | Construct directly from raw HMAC key bytes. |
| `sign(id, timestamp, payload)` | Returns a single `v1,<base64>` signature. `timestamp` is unix seconds or a `SysTime`. |
| `signHeaders(id, timestamp, payload)` | Returns the `webhook-id` / `webhook-timestamp` / `webhook-signature` headers as an associative array. |
| `verify(payload, headers)` | Verifies signature **and** timestamp; returns the payload or throws. |
| `verifyIgnoringTimestamp(payload, headers)` | Verifies the signature only (no replay-window check). |
| `toleranceSeconds` | Field; the replay window in seconds (default 300). |

Header lookup is case-insensitive and also accepts the Svix-branded
`svix-id` / `svix-timestamp` / `svix-signature` aliases as a fallback, so
payloads from Svix-powered senders verify without remapping.

### Signature scheme

The signed content is the literal string `{id}.{timestamp}.{payload}`, HMAC'd
with SHA-256 under the decoded secret, then standard-base64 encoded. The
`webhook-signature` header is a space-delimited list of `v1,<sig>` entries
(supporting zero-downtime secret rotation); verification succeeds if **any**
`v1` entry matches in constant time. Entries with other versions are skipped.
As an intentional anti-amplification divergence from the reference libraries,
at most 64 signature entries are examined per header; any beyond that cap are
ignored, which stays well above any realistic key-rotation overlap.

The core implements the symmetric (HMAC, `whsec_`, `v1`) scheme, which is what
every official reference library ships, and treats unknown versions (including
`v1a`) as skip-not-error. The spec's asymmetric `v1a` (ed25519) scheme is
available as the optional
[`standardwebhooks:ed25519`](#asymmetric-ed25519-signatures) subpackage.

## vibe.d integration

The `standardwebhooks:vibe` subpackage adds one-call helpers for vibe.d HTTP:

```sh
dub add standardwebhooks:vibe
```

```d
import standardwebhooks;
import standardwebhooks.vibe;
import vibe.http.server;

void handler(HTTPServerRequest req, HTTPServerResponse res)
{
    auto wh = Webhook("whsec_...");
    try
    {
        auto payload = wh.verifyRequest(req);  // reads body + headers, verifies
        res.writeBody("ok");
    }
    catch (WebhookVerificationException)
    {
        res.statusCode = HTTPStatus.badRequest;
        res.writeBody("invalid signature");
    }
}
```

For outgoing requests, `signRequest(wh, clientReq, id, timestamp, payload)` sets
the three headers; send `payload` as the body so the signed bytes match the sent
bytes.

## Asymmetric (ed25519) signatures

The spec also defines an **asymmetric** scheme (`v1a`): the sender signs with an
ed25519 private key and receivers verify with the matching public key, so a
leaked verifier cannot forge messages. This is provided by the optional
`standardwebhooks:ed25519` subpackage, which links the system **libsodium** for
the ed25519 primitives (so it is kept out of the dependency-free core).

```sh
# Install libsodium first: apt-get install libsodium-dev | brew install libsodium
dub add standardwebhooks:ed25519
```

**libsodium 1.0.4 or newer** is required (the detached ed25519 API the subpackage
calls). On first use the linked library's reported version is checked, and a
`WebhookVerificationException` is thrown if it is too old.

On macOS the subpackage searches the Homebrew (`/opt/homebrew/lib`,
`/usr/local/lib`) and MacPorts (`/opt/local/lib`) prefixes. If libsodium lives
elsewhere — Nix, a custom prefix, or another package manager — supply your own
`-L<dir>` linker flag (e.g. via dub's `lflags` or `LDFLAGS`) so the linker can
find it.

On Windows there is no system libsodium; install it with
[vcpkg](https://vcpkg.io) (`vcpkg install libsodium:x64-windows`) so the import
library is on the linker's `LIB` path and the matching DLL is on `PATH` at
runtime — mirroring what CI does. The subpackage links `libsodium` via dub's
`libs-windows`.

```d
import standardwebhooks;
import standardwebhooks.ed25519;

// Sender holds a whsk_ signing key (or derive one from a 32-byte seed via
// AsymmetricWebhook.fromSeed); it can both sign and verify.
auto signer = AsymmetricWebhook("whsk_...");
auto headers = signer.signHeaders("msg_2b3c", 1614265330, `{"event":"ping"}`);
// signer.publicKeyEncoded() yields the whpk_ string to hand to receivers.

// Receiver holds only the whpk_ public key; it can verify but never sign.
auto verifier = AsymmetricWebhook("whpk_...");
auto payload = verifier.verify(`{"event":"ping"}`, headers);
```

`AsymmetricWebhook` mirrors the `Webhook` API — `sign`, `signHeaders`, `verify`,
`verifyIgnoringTimestamp`, and the `toleranceSeconds` field all behave the same,
with the same case-insensitive/`svix-*` header handling and replay window. Keys
use the Standard Webhooks serialisation: `whsk_` + base64 of the 64-byte
`seed ‖ public_key`, and `whpk_` + base64 of the 32-byte public key. Calling
`sign` on a verify-only (`whpk_`) instance throws with
`WebhookError.signingKeyRequired`.

See [`examples/asymmetric`](examples/asymmetric) for a runnable end-to-end demo.

## Security

- **Constant-time comparison.** Signatures are compared without short-circuiting
  to avoid timing side channels.
- **Replay protection.** Payloads older or newer than `toleranceSeconds` (±5
  minutes by default) are rejected.
- **Verify the raw body.** Always verify the exact bytes you received, before
  parsing. Re-serializing JSON first will change the bytes and break
  verification — that is by design.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```sh
just build   # dub build
just test    # dub test (unit tests, incl. the reference vectors)
just fmt     # dfmt --inplace
just lint    # dscanner static analysis
```

(Or use `dub` directly; prefix with `ulimit -n 65536 &&` if your terminal sets a
huge file-descriptor limit — see [CONTRIBUTING.md](CONTRIBUTING.md).)

## License

[MIT](LICENSE). The Standard Webhooks specification is also MIT-licensed by its
authors; see [NOTICE](NOTICE).
