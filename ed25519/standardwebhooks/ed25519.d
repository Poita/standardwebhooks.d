/**
 * Asymmetric (ed25519) Standard Webhooks signing and verification.
 *
 * This is the spec's `v1a` signature scheme: the same
 * `{id}.{timestamp}.{payload}` content as the symmetric `v1` scheme, signed with
 * an ed25519 private key and verified with the matching public key. Unlike the
 * symmetric scheme, the verifier holds only a public key, so a leaked verifier
 * cannot forge messages.
 *
 * Keys use the Standard Webhooks serialisation: a `whsk_`-prefixed base64
 * signing key (64 bytes, `seed ‖ public_key`) and a `whpk_`-prefixed base64
 * public key (32 bytes). Construct an $(LREF AsymmetricWebhook) from either —
 * from a `whsk_` key it can both sign and verify; from a `whpk_` key it can only
 * verify.
 *
 * This subpackage links the system libsodium for the ed25519 primitives, so it
 * is kept out of the dependency-free core. Depend on `standardwebhooks:ed25519`
 * and `import standardwebhooks.ed25519;`.
 *
 * Example:
 * ---
 * // Receiver holds only the public key.
 * auto verifier = AsymmetricWebhook("whpk_1SiA4o9hyqTCpIqC5V9HUakiiaeACeqfZTInDBbOir4=");
 * verifier.verify(payload, headers);
 *
 * // Sender holds the signing key.
 * auto signer = AsymmetricWebhook("whsk_...");
 * auto headers = signer.signHeaders("msg_2b3c", 1614265330, `{"event":"ping"}`);
 * ---
 */
module standardwebhooks.ed25519;

import std.base64 : Base64;
import std.conv : to;
import std.datetime.systime : SysTime;

import standardwebhooks;
import standardwebhooks.internal;
import standardwebhooks.sodium;

@safe:

/// The signature version tag the asymmetric scheme produces and accepts.
private enum string asymmetricVersion = "v1a";

/// The prefix that brands a base64 ed25519 public (verify-only) key.
private enum string publicKeyPrefix = "whpk_";
/// The prefix that brands a base64 ed25519 signing key.
private enum string signingKeyPrefix = "whsk_";

/**
 * Signs and verifies Standard Webhooks payloads with an ed25519 key pair.
 *
 * Constructed from a `whpk_` public key (verify only) or a `whsk_` signing key
 * (sign and verify), or generated deterministically from a 32-byte seed via
 * $(LREF fromSeed). The type is a lightweight value: copying it shares the
 * immutable key bytes.
 */
struct AsymmetricWebhook
{
	private immutable(ubyte)[] publicKey;
	/// The 64-byte libsodium secret key (`seed ‖ public_key`), or empty when the
	/// instance was built from a public key alone.
	private immutable(ubyte)[] secretKey;

	/// The timestamp tolerance window in unix seconds; defaults to
	/// $(REF defaultToleranceSeconds, standardwebhooks,webhook) (five minutes).
	/// The window is symmetric: a message verifies when its timestamp lies
	/// within `±toleranceSeconds` of the current time, guarding against both
	/// stale (replayed) and future-dated payloads. A value `<= 0` rejects
	/// nearly every message, while a very large value effectively disables
	/// replay protection by accepting arbitrarily old timestamps.
	long toleranceSeconds = defaultToleranceSeconds;

	/**
	 * Builds an `AsymmetricWebhook` from a serialised key.
	 *
	 * A `whsk_` key yields an instance that can both sign and verify; a `whpk_`
	 * key yields a verify-only instance.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   with `emptySecret` for an empty string, or `invalidSecret` if the prefix
	 *   is unrecognised, the base64 is malformed, or the decoded key is the wrong
	 *   length.
	 */
	this(string key)
	{
		if (key.length == 0)
			throw new WebhookVerificationException("Key can't be empty.", WebhookError.emptySecret);

		if (hasPrefix(key, signingKeyPrefix))
		{
			auto bytes = decodePrefixedKey(key, signingKeyPrefix);
			if (bytes.length != secretKeyBytes)
				throw new WebhookVerificationException("Invalid ed25519 signing key length",
						WebhookError.invalidSecret);
			this.secretKey = bytes;
			this.publicKey = bytes[seedBytes .. $];
		}
		else if (hasPrefix(key, publicKeyPrefix))
		{
			auto bytes = decodePrefixedKey(key, publicKeyPrefix);
			if (bytes.length != publicKeyBytes)
				throw new WebhookVerificationException("Invalid ed25519 public key length",
						WebhookError.invalidSecret);
			this.publicKey = bytes;
		}
		else
			throw new WebhookVerificationException(
					"Asymmetric key must be prefixed with whsk_ or whpk_",
					WebhookError.invalidSecret);
	}

	/**
	 * Derives a sign-and-verify `AsymmetricWebhook` from a 32-byte ed25519 seed.
	 * The seed should come from a cryptographically secure source.
	 *
	 * This is the asymmetric scheme's key-generation entry point; the symmetric
	 * $(REF Webhook, standardwebhooks,webhook) has no equivalent and is instead
	 * constructed directly from an existing secret string or raw key bytes via
	 * its `fromRaw`.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   with `invalidSecret` if `seed` is not exactly 32 bytes.
	 */
	static AsymmetricWebhook fromSeed(scope const(ubyte)[] seed)
	{
		if (seed.length != seedBytes)
			throw new WebhookVerificationException("ed25519 seed must be 32 bytes",
					WebhookError.invalidSecret);

		ubyte[publicKeyBytes] pk;
		ubyte[secretKeyBytes] sk;
		if (()@trusted {
				ensureSodiumInitialised();
				return crypto_sign_seed_keypair(pk.ptr, sk.ptr, seed.ptr);
			}() != 0)
			throw new WebhookVerificationException("ed25519 key derivation failed",
					WebhookError.cryptoFailure);

		AsymmetricWebhook wh;
		wh.publicKey = pk.idup;
		wh.secretKey = sk.idup;
		return wh;
	}

	/// Whether this instance holds a signing key and so can $(LREF sign).
	bool canSign() const
	{
		return secretKey.length != 0;
	}

	/// The public key in `whpk_`-prefixed base64 form — the value a sender shares
	/// with receivers so they can verify.
	string publicKeyEncoded() const
	{
		return publicKeyPrefix ~ Base64.encode(publicKey).idup;
	}

	/**
	 * The signing key in `whsk_`-prefixed base64 form.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   with `signingKeyRequired` if this is a verify-only instance.
	 */
	string signingKeyEncoded() const
	{
		requireSigningKey();
		return signingKeyPrefix ~ Base64.encode(secretKey).idup;
	}

	/**
	 * Signs `payload` and returns a single versioned signature of the form
	 * `v1a,<base64>` — the value to place in (or append to) the
	 * `webhook-signature` header.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   with `signingKeyRequired` if this is a verify-only instance, or with
	 *   `cryptoFailure` if libsodium fails to initialise.
	 */
	string sign(string msgId, long timestamp, scope const(char)[] payload) const
	{
		requireSigningKey();
		const content = buildSignedContent(msgId, timestamp.to!string, payload);
		return asymmetricVersion ~ "," ~ signDetached(secretKey, content);
	}

	/// Convenience overload taking a `SysTime`; truncates to unix seconds.
	string sign(string msgId, SysTime timestamp, scope const(char)[] payload) const
	{
		return sign(msgId, timestamp.toUnixTime(), payload);
	}

	/**
	 * Signs `payload` and returns the three Standard Webhooks headers ready to
	 * attach to an outgoing HTTP request.
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
	 * Verifies that `payload` carries a valid `v1a` signature for the given
	 * headers and that its timestamp is within tolerance of now.
	 *
	 * Header keys are matched case-insensitively, with the Svix-branded `svix-*`
	 * aliases accepted as a fallback, exactly as in the symmetric scheme.
	 *
	 * Returns: `payload` unchanged, for convenient chaining.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   if a required header is missing, the timestamp is unparseable or outside
	 *   tolerance, no signature matches, or libsodium fails to initialise.
	 *
	 * A blanket `catch -> 400` is wrong here: a `cryptoFailure` cause is a
	 * server/library fault and should map to a 5xx, not a 400. Branch on
	 * `WebhookVerificationException.error` to distinguish it from the bad-request
	 * causes.
	 */
	const(char)[] verify(scope return const(char)[] payload, in string[string] headers) const
	{
		return verifyAt(payload, headers, currentUnixSeconds(), true);
	}

	/**
	 * Like $(LREF verify) but skips the timestamp tolerance check entirely. Use
	 * only when replay protection is handled elsewhere.
	 *
	 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception)
	 *   if a required header is missing, no signature matches, or libsodium fails
	 *   to initialise.
	 */
	const(char)[] verifyIgnoringTimestamp(scope return const(char)[] payload,
			in string[string] headers) const
	{
		return verifyAt(payload, headers, currentUnixSeconds(), false);
	}

	/// Verifies against an explicit `now` (unix seconds). Exposed for
	/// deterministic testing of the tolerance window.
	package const(char)[] verifyAt(scope return const(char)[] payload,
			in string[string] headers, long now, bool checkTimestamp) const
	{
		const msgId = lookupHeader(headers, headerId, "svix-id");
		const tsHeader = lookupHeader(headers, headerTimestamp, "svix-timestamp");
		const sigHeader = lookupHeader(headers, headerSignature, "svix-signature");

		if (msgId.length == 0 || tsHeader.length == 0 || sigHeader.length == 0)
			throw new WebhookVerificationException("Missing required headers",
					WebhookError.missingHeaders);

		if (checkTimestamp)
			verifyTimestamp(tsHeader, now, toleranceSeconds);

		const content = buildSignedContent(msgId, tsHeader, payload);

		const matched = anySignature(sigHeader, (scope version_, scope signature) {
			return version_ == asymmetricVersion && verifyDetached(publicKey, content, signature);
		});
		if (matched)
			return payload;

		throw new WebhookVerificationException("No matching signature found", WebhookError.noMatch);
	}

	private void requireSigningKey() const
	{
		if (secretKey.length == 0)
			throw new WebhookVerificationException("A whsk_ signing key is required to sign",
					WebhookError.signingKeyRequired);
	}
}

// --- Free helpers -----------------------------------------------------------

/// Whether `s` begins with `prefix`.
private bool hasPrefix(scope const(char)[] s, string prefix) @safe
{
	return s.length >= prefix.length && s[0 .. prefix.length] == prefix;
}

/// Produces the base64 ed25519 signature (without the `v1a,` prefix) of
/// `content` under the 64-byte secret key `sk`.
private string signDetached(scope const(ubyte)[] sk, scope const(char)[] content) @trusted
{
	ensureSodiumInitialised();
	ubyte[signatureBytes] sig;
	ulong siglen;
	if (crypto_sign_detached(sig.ptr, &siglen,
			cast(const(ubyte)*) content.ptr, content.length, sk.ptr) != 0)
		throw new WebhookVerificationException("ed25519 signing failed", WebhookError.cryptoFailure);
	assert(siglen == signatureBytes);
	return Base64.encode(sig[0 .. siglen]).idup;
}

/// Verifies a base64 ed25519 `signature` over `content` against public key `pk`.
/// A malformed or wrong-length signature returns false rather than throwing.
private bool verifyDetached(scope const(ubyte)[] pk, scope const(char)[] content,
		scope const(char)[] signature) @trusted
{
	ensureSodiumInitialised();

	// The spec mandates canonical standard padded base64 for v1a signatures, as
	// the symmetric v1 scheme requires. Reject an unpadded length here so the
	// padding-tolerant core decode cannot silently accept a non-canonical value.
	if (signature.length % 4 != 0)
		return false;

	immutable(ubyte)[] decoded;
	try
		decoded = decodeStdBase64(signature);
	catch (Exception)
		return false;

	if (decoded.length != signatureBytes)
		return false;

	return crypto_sign_verify_detached(decoded.ptr,
			cast(const(ubyte)*) content.ptr, content.length, pk.ptr) == 0;
}

// --- Tests ------------------------------------------------------------------
// Golden vector from the Svix server's `test_asymmetric_key_signing`, the
// de-facto reference for the spec's `v1a` scheme.

version (unittest)
{
	private enum vecSigningKey = "whsk_6Xb/dCcHpPea21PS1N9VY/NZW723CEc77N4rJCubMbfVKIDij2HKpMKkioLlX0dRqSKJp4AJ6p9lMicMFs6Kvg==";
	private enum vecPublicKey = "whpk_1SiA4o9hyqTCpIqC5V9HUakiiaeACeqfZTInDBbOir4=";
	private enum vecSeedB64 = "6Xb/dCcHpPea21PS1N9VY/NZW723CEc77N4rJCubMbc=";
	private enum vecId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
	private enum vecTimestamp = 1_614_265_330L;
	private enum vecPayload = `{"test": 2432232314}`;
	private enum vecSignature = "v1a,hnO3f9T8Ytu9HwrXslvumlUpqtNVqkhqw/enGzPCXe5BdqzCInXqYXFymVJaA7AZdpXwVLPo3mNl8EM+m7TBAg==";
}

/// sign() reproduces the official asymmetric reference vector exactly.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecSigningKey);
	assert(wh.sign(vecId, vecTimestamp, vecPayload) == vecSignature);
}

/// A verify-only `whpk_` instance accepts the reference signature.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: vecSignature,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// A signing key verifies its own freshly produced signature end to end.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecSigningKey);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// fromSeed() reconstructs the same key pair as the serialised golden key.
@safe unittest
{
	auto seed = Base64.decode(vecSeedB64);
	auto wh = AsymmetricWebhook.fromSeed(seed);
	assert(wh.publicKeyEncoded() == vecPublicKey);
	assert(wh.sign(vecId, vecTimestamp, vecPayload) == vecSignature);
}

/// A signing key round-trips through its `whsk_` encoding.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecSigningKey);
	assert(wh.signingKeyEncoded() == vecSigningKey);
}

/// canSign reflects whether a signing key is present.
@safe unittest
{
	assert(AsymmetricWebhook(vecSigningKey).canSign());
	assert(!AsymmetricWebhook(vecPublicKey).canSign());
}

/// A tampered signature does not verify (the final base64 char is flipped).
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = AsymmetricWebhook(vecPublicKey);
	auto tampered = vecSignature[0 .. $ - 3] ~ "AAg==";
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: tampered,
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// A tampered payload does not verify against a valid signature.
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: vecSignature,
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(`{"test": 2432232315}`,
			headers, vecTimestamp, false));
}

/// A valid `v1a` signature is found alongside a symmetric `v1` decoy entry.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: "v1,AAAA " ~ vecSignature,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// A different public key rejects an otherwise valid signature.
@safe unittest
{
	import std.exception : assertThrown;

	ubyte[seedBytes] otherSeed = 7;
	auto other = AsymmetricWebhook.fromSeed(otherSeed[]);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: vecSignature,
	];
	assertThrown!WebhookVerificationException(other.verifyAt(vecPayload,
			headers, vecTimestamp, false));
}

/// A verify-only instance cannot sign.
@safe unittest
{
	import std.exception : collectException;

	auto wh = AsymmetricWebhook(vecPublicKey);
	auto ex = collectException!WebhookVerificationException(wh.sign(vecId,
			vecTimestamp, vecPayload));
	assert(ex !is null && ex.error == WebhookError.signingKeyRequired);
}

/// A verify-only instance has no `whsk_` encoding to hand out.
@safe unittest
{
	import std.exception : collectException;

	auto wh = AsymmetricWebhook(vecPublicKey);
	auto ex = collectException!WebhookVerificationException(wh.signingKeyEncoded());
	assert(ex !is null && ex.error == WebhookError.signingKeyRequired);
}

/// An unrecognised key prefix is rejected.
@safe unittest
{
	import std.exception : collectException;

	auto ex = collectException!WebhookVerificationException(
			AsymmetricWebhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"));
	assert(ex !is null && ex.error == WebhookError.invalidSecret);
}

/// A `whpk_` key of the wrong length is rejected.
@safe unittest
{
	import std.exception : collectException;

	auto ex = collectException!WebhookVerificationException(AsymmetricWebhook("whpk_AAAA"));
	assert(ex !is null && ex.error == WebhookError.invalidSecret);
}

/// An empty key is rejected.
@safe unittest
{
	import std.exception : collectException;

	auto ex = collectException!WebhookVerificationException(AsymmetricWebhook(""));
	assert(ex !is null && ex.error == WebhookError.emptySecret);
}

/// A timestamp outside tolerance is rejected even with a valid signature.
@safe unittest
{
	import std.exception : collectException;

	auto wh = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: vecSignature,
	];
	auto ex = collectException!WebhookVerificationException(wh.verifyAt(vecPayload,
			headers, vecTimestamp + 301, true));
	assert(ex !is null && ex.error == WebhookError.timestampTooOld);
}

/// Svix-branded header aliases are accepted as a fallback.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [
		"svix-id": vecId, "svix-timestamp": vecTimestamp.to!string,
		"svix-signature": vecSignature,
	];
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// A signature carrying base64URL alphabet characters (`-`/`_`) is rejected
/// rather than mis-decoded: verifyDetached fails the standard-base64 decode and
/// returns false, so verification throws.
@safe unittest
{
	import std.exception : assertThrown;

	auto wh = AsymmetricWebhook(vecPublicKey);
	// The genuine signature with two standard-base64 chars swapped for their
	// base64URL equivalents, so a strict decoder must reject it.
	auto urlEncoded = asymmetricVersion ~ ",hnO3f9T8Ytu9HwrXslvumlUpqtNVqkhqw_enGzPCXe5Bdqz"
		~ "CInXqYXFymVJaA7AZdpXwVLPo3mNl8EM-m7TBAg==";
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: urlEncoded,
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// Signing and verification work without an eager module ctor: libsodium is
/// initialised lazily on the first crypto call.
@safe unittest
{
	auto wh = AsymmetricWebhook(vecSigningKey);
	auto headers = wh.signHeaders(vecId, vecTimestamp, vecPayload);
	assert(wh.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}

/// fromSeed() derives the golden public key from its 32-byte seed.
@safe unittest
{
	auto seed = Base64.decode(vecSeedB64);
	auto wh = AsymmetricWebhook.fromSeed(seed);
	assert(wh.publicKeyEncoded() == vecPublicKey);
}

/// The public verify() uses the real clock: a payload signed at the current time
/// passes without an injected `now`.
@safe unittest
{
	import std.datetime.systime : Clock;
	import std.datetime.timezone : UTC;

	auto wh = AsymmetricWebhook(vecSigningKey);
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

	auto wh = AsymmetricWebhook(vecSigningKey);
	const old = Clock.currTime(UTC()).toUnixTime() - 1000;
	auto headers = wh.signHeaders(vecId, old, vecPayload);
	auto ex = collectException!WebhookVerificationException(wh.verify(vecPayload, headers));
	assert(ex !is null && ex.error == WebhookError.timestampTooOld);
}

/// A `whsk_` signing key of the wrong length is rejected.
@safe unittest
{
	import std.exception : collectException;

	auto ex = collectException!WebhookVerificationException(AsymmetricWebhook("whsk_AAAA"));
	assert(ex !is null && ex.error == WebhookError.invalidSecret);
}

/// fromSeed() rejects a seed that is not 32 bytes.
@safe unittest
{
	import std.exception : collectException;

	ubyte[16] shortSeed = 0;
	auto ex = collectException!WebhookVerificationException(AsymmetricWebhook.fromSeed(shortSeed[]));
	assert(ex !is null && ex.error == WebhookError.invalidSecret);
}

/// verify() rejects headers missing a required entry.
@safe unittest
{
	import std.exception : collectException;

	auto wh = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [headerId: vecId, headerSignature: vecSignature,];
	auto ex = collectException!WebhookVerificationException(wh.verify(vecPayload, headers));
	assert(ex !is null && ex.error == WebhookError.missingHeaders);
}

/// An unpadded (non-canonical) signature is rejected: the spec mandates standard
/// padded base64 for `v1a`, matching `v1`, so a stripped-padding signature must
/// fail verification rather than be silently re-padded.
@safe unittest
{
	import std.algorithm.searching : endsWith;
	import std.exception : assertThrown;

	auto wh = AsymmetricWebhook(vecPublicKey);
	auto unpadded = vecSignature;
	while (unpadded.endsWith("="))
		unpadded = unpadded[0 .. $ - 1];
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: unpadded,
	];
	assertThrown!WebhookVerificationException(wh.verifyAt(vecPayload, headers, vecTimestamp, false));
}

/// A freshly signed payload round-trips through verify after the crypto
/// hardening, confirming the ed25519 primitives still operate normally.
@safe unittest
{
	auto signer = AsymmetricWebhook(vecSigningKey);
	auto sig = signer.sign(vecId, vecTimestamp, vecPayload);
	auto verifier = AsymmetricWebhook(vecPublicKey);
	string[string] headers = [
		headerId: vecId, headerTimestamp: vecTimestamp.to!string,
		headerSignature: sig,
	];
	assert(verifier.verifyAt(vecPayload, headers, vecTimestamp, false) == vecPayload);
}
