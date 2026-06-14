/**
 * A faithful D implementation of the
 * $(LINK2 https://www.standardwebhooks.com/, Standard Webhooks) signing and
 * verification scheme.
 *
 * Standard Webhooks signs the tuple `{id}.{timestamp}.{payload}` with
 * HMAC-SHA256 and a shared secret, base64-encodes the digest, and carries it in
 * a `webhook-signature` header alongside `webhook-id` and `webhook-timestamp`.
 * Verification recomputes the signature, compares it in constant time, and
 * rejects payloads whose timestamp is outside a tolerance window.
 *
 * The core is dependency-free (Phobos only). For vibe.d HTTP integration, depend
 * on the `standardwebhooks:vibe` subpackage and import `standardwebhooks.vibe`.
 *
 * Example:
 * ---
 * auto wh = Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
 *
 * // Sender side: build the headers for an outgoing request.
 * auto headers = wh.signHeaders("msg_2b3c", 1614265330, `{"event":"ping"}`);
 *
 * // Receiver side: verify an incoming request, throwing on any mismatch.
 * string payload = wh.verify(`{"event":"ping"}`, headers);
 * ---
 */
module standardwebhooks.webhook;

import std.base64 : Base64;
import std.conv : to;
import std.datetime.systime : SysTime;
import std.digest.hmac : HMAC;
import std.digest.sha : SHA256;

import standardwebhooks.exception;
import standardwebhooks.internal;

@safe:

/// Canonical Standard Webhooks header carrying the unique message id.
enum string headerId = wireHeaderId;
/// Canonical Standard Webhooks header carrying the unix-seconds timestamp.
enum string headerTimestamp = wireHeaderTimestamp;
/// Canonical Standard Webhooks header carrying the space-delimited signatures.
enum string headerSignature = wireHeaderSignature;

/// The default timestamp tolerance: five minutes, applied symmetrically.
enum long defaultToleranceSeconds = 5 * 60;

/// The prefix that brands a base64 symmetric secret.
private enum string secretPrefix = "whsec_";

/// The only signature version this library produces and accepts. Entries with
/// any other version (e.g. the spec's asymmetric `v1a`) are skipped, not
/// errored, during verification — matching every reference library.
private enum string signatureVersion = "v1";

/**
 * Signs and verifies Standard Webhooks payloads with a single shared secret.
 *
 * Construct from a `whsec_`-prefixed (or bare) base64 secret, or from raw key
 * bytes via $(LREF fromRaw). The type is a lightweight value: copying it shares
 * the immutable key.
 */
struct Webhook
{
	private immutable(ubyte)[] key;

	/// The timestamp tolerance window in unix seconds. Public so callers may
	/// widen or narrow it; defaults to $(LREF defaultToleranceSeconds) (five
	/// minutes). The window is symmetric: a message verifies when its timestamp
	/// lies within `±toleranceSeconds` of the current time, guarding against
	/// both stale (replayed) and future-dated payloads. A value `<= 0` rejects
	/// nearly every message, while a very large value effectively disables
	/// replay protection by accepting arbitrarily old timestamps.
	long toleranceSeconds = defaultToleranceSeconds;

	/**
	 * Builds a `Webhook` from a base64 secret.
	 *
	 * The secret may carry the conventional `whsec_` prefix or omit it; either
	 * way the remainder is base64-decoded to the HMAC key. Unpadded base64 is
	 * accepted (the decoder pads it), so secrets that have had trailing `=`
	 * stripped still work.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   with `WebhookError.emptySecret` for an empty string, or
	 *   `WebhookError.invalidSecret` if the remainder is not valid base64.
	 */
	this(string secret)
	{
		this.key = decodePrefixedKey(secret, secretPrefix);
	}

	/**
	 * Builds a `Webhook` directly from raw HMAC key bytes, bypassing the
	 * `whsec_`/base64 convention. Use this when the key is already binary (for
	 * example, freshly generated random bytes).
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   with `WebhookError.emptySecret` for a zero-length key, which would
	 *   otherwise sign and verify a worthless signature with no diagnostic.
	 */
	static Webhook fromRaw(scope const(ubyte)[] key)
	{
		if (key.length == 0)
			throw new WebhookVerificationException("Empty signing key", WebhookError.emptySecret);
		Webhook wh;
		wh.key = key.idup;
		return wh;
	}

	/// The shared secret in `whsec_`-prefixed base64 form — the value to store or
	/// hand to a counterparty so it can reconstruct an identical `Webhook`.
	string secretEncoded() const
	{
		return secretPrefix ~ Base64.encode(key).idup;
	}

	/**
	 * Returns a copy of this `Webhook` with its timestamp tolerance set to
	 * `seconds`, sharing the same key. Tolerance is key-independent, so the copy
	 * preserves every invariant; this enables fluent construction such as
	 * `Webhook(secret).withTolerance(600).verify(...)`.
	 */
	Webhook withTolerance(long seconds) const
	{
		Webhook wh;
		wh.key = this.key;
		wh.toleranceSeconds = seconds;
		return wh;
	}

	/**
	 * Signs `payload` and returns a single versioned signature of the form
	 * `v1,<base64>` — the value to place in (or append to) the
	 * `webhook-signature` header.
	 *
	 * `timestamp` is unix seconds. The signed content is the literal
	 * `{msgId}.{timestamp}.{payload}`, so the exact `timestamp` passed here must
	 * also be the value sent in the `webhook-timestamp` header.
	 */
	string sign(string msgId, long timestamp, scope const(char)[] payload) const
	{
		return signatureVersion ~ "," ~ signRaw(msgId, timestamp.to!string, payload);
	}

	/// Convenience overload taking a `SysTime`; truncates to unix seconds.
	string sign(string msgId, SysTime timestamp, scope const(char)[] payload) const
	{
		return sign(msgId, timestamp.toUnixTime(), payload);
	}

	/**
	 * Signs `payload` and returns the three Standard Webhooks headers ready to
	 * attach to an outgoing HTTP request: `webhook-id`, `webhook-timestamp` and
	 * `webhook-signature`.
	 */
	string[string] signHeaders(string msgId, long timestamp, scope const(char)[] payload) const
	{
		return [
			headerId: msgId,
			headerTimestamp: timestamp.to!string,
			headerSignature: sign(msgId, timestamp, payload),
		];
	}

	/**
	 * Verifies that `payload` carries a valid signature for the given headers
	 * and that its timestamp is within tolerance of now.
	 *
	 * Header keys are matched case-insensitively. In addition to the canonical
	 * `webhook-*` names, the Svix-branded `svix-id` / `svix-timestamp` /
	 * `svix-signature` aliases are accepted as a fallback, so payloads from
	 * Svix-powered senders verify without remapping.
	 *
	 * Returns: `payload` unchanged, for convenient chaining.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   if a required header is missing, the timestamp is unparseable or outside
	 *   tolerance, or no signature matches.
	 */
	const(char)[] verify(scope return const(char)[] payload, in string[string] headers) const
	{
		return throwOnFailure(tryVerify(payload, headers));
	}

	/**
	 * Like $(LREF verify) but skips the timestamp tolerance check entirely. Use
	 * only when replay protection is handled elsewhere; it removes a key defence
	 * of the scheme.
	 */
	const(char)[] verifyIgnoringTimestamp(scope return const(char)[] payload,
			in string[string] headers) const
	{
		return throwOnFailure(tryVerifyIgnoringTimestamp(payload, headers));
	}

	/**
	 * Verifies `payload` against `headers` without throwing, returning a
	 * $(REF VerifyResult, standardwebhooks,exception). An invalid inbound
	 * signature is routine control flow for a receiver, so callers branch on the
	 * result's `error` instead of catching. The throwing $(LREF verify) is built
	 * on this, so the two stay in lock-step.
	 *
	 * Header matching and the timestamp window behave exactly as in $(LREF verify).
	 */
	VerifyResult tryVerify(scope return const(char)[] payload, in string[string] headers) const
	{
		return tryVerifyAt(payload, headers, currentUnixSeconds(), true);
	}

	/**
	 * Like $(LREF tryVerify) but skips the timestamp tolerance check entirely. Use
	 * only when replay protection is handled elsewhere; it removes a key defence
	 * of the scheme.
	 */
	VerifyResult tryVerifyIgnoringTimestamp(scope return const(char)[] payload,
			in string[string] headers) const
	{
		return tryVerifyAt(payload, headers, currentUnixSeconds(), false);
	}

	/// Verifies against an explicit `now` (unix seconds). Exposed for
	/// deterministic testing of the tolerance window.
	package const(char)[] verifyAt(scope return const(char)[] payload,
			in string[string] headers, long now, bool checkTimestamp) const scope
	{
		return throwOnFailure(tryVerifyAt(payload, headers, now, checkTimestamp));
	}

	/// The non-throwing verification core, against an explicit `now`. Exposed for
	/// deterministic testing of the tolerance window.
	package VerifyResult tryVerifyAt(scope return const(char)[] payload,
			in string[string] headers, long now, bool checkTimestamp) const scope
	{
		const(char)[] msgId, tsHeader, sigHeader;
		WebhookError error;
		if (!tryRequireHeaders(headers, now, checkTimestamp, toleranceSeconds,
				msgId, tsHeader, sigHeader, error))
			return VerifyResult(false, error);

		// The signed content uses the timestamp header string verbatim — not a
		// reparsed integer — so a sender's exact formatting round-trips.
		const expected = signRaw(msgId, tsHeader, payload);

		// Both operands are the base64 encoding of the HMAC, and the comparison
		// runs over that encoded form on purpose. Base64 is a deterministic
		// bijection, so constant-time equality over the encoding is constant-time
		// over the underlying digest. Do not change this to decode first: that
		// adds a hot-path allocation and a malformed-input oracle for no gain.
		const matched = anySignature(sigHeader, (scope version_, scope signature) {
			return version_ == signatureVersion && constantTimeEquals(signature, expected);
		});
		if (matched)
			return VerifyResult(true, WebhookError.init, payload);

		return VerifyResult(false, WebhookError.noMatch);
	}

	/// Computes the bare base64 HMAC-SHA256 signature (without the `v1,` prefix).
	/// Rejects an empty key, which catches `Webhook.init` whose key was never
	/// set; signing or verifying with it would yield a worthless signature.
	private string signRaw(scope const(char)[] msgId, scope const(char)[] tsStr,
			scope const(char)[] payload) const scope
	{
		if (key.length == 0)
			throw new WebhookVerificationException("Empty signing key", WebhookError.emptySecret);
		return hmacBase64(key, buildSignedContent(msgId, tsStr, payload));
	}
}

// --- Free helpers -----------------------------------------------------------

/// HMAC-SHA256 of `content` under `key`, standard-base64 encoded (padded).
private string hmacBase64(scope const(ubyte)[] key, scope const(char)[] content) @safe
{
	auto mac = HMAC!SHA256(key);
	mac.put(cast(const(ubyte)[]) content);
	auto digest = mac.finish();
	return Base64.encode(digest[]).idup;
}

/// Length-checked, non-short-circuiting byte comparison. A length mismatch
/// returns immediately (as in every reference library); equal-length inputs are
/// compared in time independent of where they first differ.
private bool constantTimeEquals(scope const(char)[] a, scope const(char)[] b) @safe @nogc nothrow pure
{
	if (a.length != b.length)
		return false;
	uint diff = 0;
	foreach (i; 0 .. a.length)
		diff |= cast(uint)(a[i] ^ b[i]);
	return diff == 0;
}

// --- Tests ------------------------------------------------------------------
// Golden vectors and edge cases ported from the official reference libraries.

version (unittest)
{
	// The canonical reference vector (Python `test_sign_function`).
	private enum vecSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
	private enum vecId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
	private enum vecTimestamp = 1_614_265_330L;
	private enum vecPayload = `{"test": 2432232314}`;
	private enum vecSignature = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
}

/// sign() reproduces the canonical reference vector exactly.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	assert(wh.sign(vecId, vecTimestamp, vecPayload) == vecSignature);
}

/// A second independent reference vector (Rust `test_sign`).
@safe unittest
{
	auto wh = Webhook("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD");
	auto sig = wh.sign("msg_27UH4WbU6Z5A5EzD8u03UvzRbpk", 1_649_367_553L,
			`{"email":"test@example.com","username":"test_user"}`);
	assert(sig == "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw=");
}

/// verify() accepts a payload signed with the same secret.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// A secret without the `whsec_` prefix decodes identically.
@safe unittest
{
	auto prefixed = Webhook(vecSecret);
	auto bare = Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
	assert(prefixed.sign(vecId, vecTimestamp, vecPayload) == bare.sign(vecId,
			vecTimestamp, vecPayload));
}

/// An unpadded base64 secret still verifies (Python
/// `test_signature_verification_with_unpadded_secret`).
@safe unittest
{
	// "test-key" base64 is "dGVzdC1rZXk=" (one pad char); strip it.
	auto padded = Webhook("whsec_dGVzdC1rZXk=");
	auto unpadded = Webhook("whsec_dGVzdC1rZXk");
	assert(padded.sign(vecId, vecTimestamp, vecPayload) == unpadded.sign(vecId,
			vecTimestamp, vecPayload));
}

/// fromRaw() signs with the key bytes directly (no base64 decode).
@safe unittest
{
	immutable(ubyte)[] raw = [1, 2, 3, 4, 5, 6, 7, 8];
	auto wh = Webhook.fromRaw(raw);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// An empty secret is rejected.
@safe unittest
{
	import std.exception : assertThrown;

	assertThrown!WebhookVerificationException(Webhook(""));
}

/// secretEncoded() round-trips: re-prefixing and re-decoding yields the same key.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto roundTrip = Webhook(wh.secretEncoded());
	assert(roundTrip.sign(vecId, vecTimestamp, vecPayload) == vecSignature);
}

/// secretEncoded() carries the `whsec_` prefix and re-encodes a bare secret with it.
@safe unittest
{
	auto bare = Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
	assert(bare.secretEncoded() == vecSecret);
}

/// secretEncoded() of a fromRaw() instance base64-encodes the raw key bytes.
@safe unittest
{
	immutable(ubyte)[] raw = [1, 2, 3, 4, 5, 6, 7, 8];
	auto wh = Webhook.fromRaw(raw);
	assert(wh.secretEncoded() == "whsec_" ~ Base64.encode(raw).idup);
}

/// fromRaw() rejects a zero-length key rather than yielding a worthless signer.
@safe unittest
{
	import std.exception : collectException;

	auto ex = collectException!WebhookVerificationException(Webhook.fromRaw([]));
	assert(ex !is null && ex.error == WebhookError.emptySecret);
}

/// A default-initialised Webhook (`Webhook.init`) has no key, so signing throws
/// rather than producing a real-looking but worthless signature.
@safe unittest
{
	import std.exception : collectException;

	Webhook wh;
	auto ex = collectException!WebhookVerificationException(wh.sign(vecId,
			vecTimestamp, vecPayload));
	assert(ex !is null && ex.error == WebhookError.emptySecret);
}

/// A default-initialised Webhook rejects verification too.
@safe unittest
{
	import std.exception : collectException;

	Webhook wh;
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: vecSignature,
	];
	auto ex = collectException!WebhookVerificationException(wh.verifyAt(vecPayload,
			headers, vecTimestamp, false));
	assert(ex !is null && ex.error == WebhookError.emptySecret);
}

/// A tampered signature does not verify (the reference negative vector flips the
/// final base64 character, `1OE=` -> `1OA=`).
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA=",
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// A valid signature is found among multiple space-delimited entries, including
/// a decoy with an unknown version.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	const good = wh.sign(vecId, vecTimestamp, vecPayload); // "v1,...."
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v2,bogus " ~ good ~ " v1,AAAA",
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// All-decoy signatures fail.
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v2,bogus v1,AAAA",
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// A genuine signature buried past the entry cap is never reached, bounding the
/// verification work an attacker can force.
@safe unittest
{
	import std.array : join;
	import std.exception : assertThrown;
	import std.range : repeat;

	auto wh = Webhook(vecSecret);
	const good = wh.sign(vecId, vecTimestamp, vecPayload);
	const decoys = "v1,AAAA".repeat(200).join(" ");
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: decoys ~ " " ~ good,
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// Malformed entries (no comma, empty signature) are skipped without crashing.
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "novalue v1,",
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// A missing `webhook-id` header is rejected.
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerTimestamp: vecTimestamp.to!string, headerSignature: vecSignature,
	];
	auto ex = collectVerifyError(wh, headers);
	assert(ex.error == WebhookError.missingHeaders);
}

/// A missing `webhook-timestamp` header is rejected.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [headerId: vecId, headerSignature: vecSignature];
	auto ex = collectVerifyError(wh, headers);
	assert(ex.error == WebhookError.missingHeaders);
}

/// A missing `webhook-signature` header is rejected.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string
	];
	auto ex = collectVerifyError(wh, headers);
	assert(ex.error == WebhookError.missingHeaders);
}

/// A non-numeric timestamp is rejected as invalid headers.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: "not-a-number",
		headerSignature: vecSignature,
	];
	auto ex = collectVerifyError(wh, headers, true);
	assert(ex.error == WebhookError.invalidHeaders);
}

/// A timestamp containing invalid UTF-8 bytes is rejected as invalid headers.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	immutable ubyte[2] bad = [0xff, 0xfe];
	string[string] headers = [
		headerId: vecId, headerTimestamp: cast(string) bad.idup,
		headerSignature: vecSignature,
	];
	auto ex = collectVerifyError(wh, headers, true);
	assert(ex.error == WebhookError.invalidHeaders);
}

/// A timestamp 301s in the past is rejected (tolerance is 300s).
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	auto ex = collectVerifyErrorAt(wh, headers, vecTimestamp + 301);
	assert(ex.error == WebhookError.timestampTooOld);
}

/// A timestamp 301s in the future is rejected.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	auto ex = collectVerifyErrorAt(wh, headers, vecTimestamp - 301);
	assert(ex.error == WebhookError.timestampTooNew);
}

/// A `long.min` timestamp is rejected as too old rather than overflowing.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: long.min.to!string,
		headerSignature: vecSignature,
	];
	auto ex = collectVerifyErrorAt(wh, headers, vecTimestamp);
	assert(ex.error == WebhookError.timestampTooOld);
}

/// Exactly 300s of skew (either direction) is accepted.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp + 300, true) == vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp - 300, true) == vecPayload);
}

/// Header keys are matched case-insensitively.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		"Webhook-Id": vecId, "Webhook-Timestamp": vecTimestamp.to!string,
		"Webhook-Signature": vecSignature,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// Svix-branded header aliases are accepted as a fallback.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		"svix-id": vecId, "svix-timestamp": vecTimestamp.to!string,
		"svix-signature": vecSignature,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// When both canonical and svix-* headers are present, the canonical values
/// win regardless of map iteration order.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		"webhook-id": vecId, "svix-id": "wrong",
		"webhook-timestamp": vecTimestamp.to!string, "svix-timestamp": "0",
		"webhook-signature": vecSignature, "svix-signature": "v1,deadbeef",
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// tryVerify reports success with the payload and no error for a valid signature.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	auto result = wh.tryVerifyAt(vecPayload, headers, vecTimestamp, false);
	assert(result.ok);
	assert(result.payload == vecPayload);
}

/// tryVerify reports failure (without throwing) for a tampered signature, naming
/// noMatch as the cause.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA=",
	];
	auto result = wh.tryVerifyAt(vecPayload, headers, vecTimestamp, false);
	assert(!result.ok);
	assert(result.error == WebhookError.noMatch);
}

/// tryVerify reports missingHeaders without throwing when a header is absent.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerTimestamp: vecTimestamp.to!string, headerSignature: vecSignature,
	];
	auto result = wh.tryVerifyAt(vecPayload, headers, vecTimestamp, false);
	assert(!result.ok);
	assert(result.error == WebhookError.missingHeaders);
}

/// tryVerify reports timestampTooOld without throwing for a stale timestamp.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	auto result = wh.tryVerifyAt(vecPayload, headers, vecTimestamp + 301, true);
	assert(!result.ok);
	assert(result.error == WebhookError.timestampTooOld);
}

/// tryVerifyIgnoringTimestamp accepts a stale timestamp, succeeding at the
/// current clock without an injected `now`.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	auto result = wh.tryVerifyIgnoringTimestamp(vecPayload, headers);
	assert(result.ok);
	assert(result.payload == vecPayload);
}

/// The public tryVerify uses the real clock: a payload signed now succeeds.
@safe unittest
{
	import std.datetime.systime : Clock;
	import std.datetime.timezone : UTC;

	auto wh = Webhook(vecSecret);
	const now = Clock.currTime(UTC()).toUnixTime();
	auto headers = wh.signHeaders(vecId, now, vecPayload);
	auto result = wh.tryVerify(vecPayload, headers);
	assert(result.ok);
	assert(result.payload == vecPayload);
}

/// The throwing verify() is built on tryVerify: when tryVerify fails, verify()
/// throws an exception carrying the same WebhookError cause.
@safe unittest
{
	import std.exception : collectException;

	auto wh = Webhook(vecSecret);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA=",
	];
	auto fromTry = wh.tryVerifyAt(vecPayload, headers, vecTimestamp, false);
	auto ex = collectException!WebhookVerificationException(wh.verifyAt(vecPayload,
			headers, vecTimestamp, false));
	assert(!fromTry.ok);
	assert(ex !is null && ex.error == fromTry.error);
}

/// constantTimeEquals agrees with `==` on representative inputs.
@safe unittest
{
	assert(constantTimeEquals("abc", "abc"));
	assert(!constantTimeEquals("abc", "abd"));
	assert(!constantTimeEquals("abc", "abcd"));
	assert(constantTimeEquals("", ""));
}

version (unittest)
{
	private WebhookVerificationException collectVerifyError(in Webhook wh,
			in string[string] headers, bool checkTs = false) @safe
	{
		import std.exception : collectException;

		auto ex = collectException!WebhookVerificationException(wh.verifyAt(vecPayload,
				headers, vecTimestamp, checkTs));
		assert(ex !is null, "expected a WebhookVerificationException");
		return ex;
	}

	private WebhookVerificationException collectVerifyErrorAt(in Webhook wh,
			in string[string] headers, long now) @safe
	{
		import std.exception : collectException;

		auto ex = collectException!WebhookVerificationException(wh.verifyAt(vecPayload,
				headers, now, true));
		assert(ex !is null, "expected a WebhookVerificationException");
		return ex;
	}
}

/// The public verify() uses the real clock: a payload signed at the current time
/// passes without an injected `now`.
@safe unittest
{
	import std.datetime.systime : Clock;
	import std.datetime.timezone : UTC;

	auto wh = Webhook(vecSecret);
	const now = Clock.currTime(UTC()).toUnixTime();
	auto headers = wh.signHeaders(vecId, now, vecPayload);
	assert(wh.verify(vecPayload, headers) == vecPayload);
}

/// The public verify() rejects a payload whose timestamp is well outside the
/// tolerance window of the real clock.
@safe unittest
{
	import std.datetime.systime : Clock;
	import std.datetime.timezone : UTC;
	import std.exception : collectException;

	auto wh = Webhook(vecSecret);
	const old = Clock.currTime(UTC()).toUnixTime() - 1000;
	auto headers = wh.signHeaders(vecId, old, vecPayload);
	auto ex = collectException!WebhookVerificationException(wh.verify(vecPayload, headers));
	assert(ex !is null && ex.error == WebhookError.timestampTooOld);
}

/// anySignature splits each entry on its first comma only, so a decoy entry
/// carrying extra commas does not stop the genuine `v1,<sig>` from matching.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	const good = wh.sign(vecId, vecTimestamp, vecPayload); // "v1,...."
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v1,a,b " ~ good,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// The entry cap is exactly 64: a genuine signature at the 65th position (after
/// 64 decoys) is never examined, so verification fails.
@safe unittest
{
	import std.array : join;
	import std.exception : assertThrown;
	import std.range : repeat;

	auto wh = Webhook(vecSecret);
	const good = wh.sign(vecId, vecTimestamp, vecPayload);
	const decoys = "v1,AAAA".repeat(64).join(" ");
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: decoys ~ " " ~ good,
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// The entry cap is exactly 64: a genuine signature at the 64th position (after
/// 63 decoys) is examined, so verification succeeds.
@safe unittest
{
	import std.array : join;
	import std.range : repeat;

	auto wh = Webhook(vecSecret);
	const good = wh.sign(vecId, vecTimestamp, vecPayload);
	const decoys = "v1,AAAA".repeat(63).join(" ");
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: decoys ~ " " ~ good,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// hmacBase64 carries plain `@safe`, not `@trusted`: its body has no genuinely
/// unsafe operation, so the audited surface stays minimal.
@safe unittest
{
	import std.traits : functionAttributes, FunctionAttribute;

	enum attrs = functionAttributes!hmacBase64;
	static assert(attrs & FunctionAttribute.safe);
	static assert(!(attrs & FunctionAttribute.trusted));
}

/// withTolerance returns a copy whose toleranceSeconds is the supplied value.
@safe unittest
{
	auto wh = Webhook(vecSecret).withTolerance(600);
	assert(wh.toleranceSeconds == 600);
}

/// withTolerance leaves the source instance's tolerance untouched.
@safe unittest
{
	auto wh = Webhook(vecSecret);
	const widened = wh.withTolerance(600);
	assert(wh.toleranceSeconds == defaultToleranceSeconds);
	assert(widened.toleranceSeconds == 600);
}

/// The copy shares the key, so a fluently-widened Webhook still verifies a
/// signature produced by the original.
@safe unittest
{
	auto wh = Webhook(vecSecret).withTolerance(600);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// A widened tolerance lets an otherwise-stale timestamp verify, proving the
/// copied toleranceSeconds is the value verification consults.
@safe unittest
{
	import std.datetime.systime : Clock;
	import std.datetime.timezone : UTC;

	const old = Clock.currTime(UTC()).toUnixTime() - 1000;
	auto wh = Webhook(vecSecret).withTolerance(2000);
	auto headers = wh.signHeaders(vecId, old, vecPayload);
	assert(wh.verify(vecPayload, headers) == vecPayload);
}
