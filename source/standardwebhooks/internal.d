/**
 * Internal helpers shared between the symmetric core
 * ($(REF Webhook, standardwebhooks,webhook)) and the asymmetric ed25519
 * subpackage ($(REF AsymmetricWebhook, standardwebhooks,ed25519)).
 *
 * Everything here is `package`-visible: it is implementation detail, not public
 * API. Both schemes route through these helpers so the wire format — the signed
 * content, the header lookup rules, the timestamp window and the signature-list
 * parsing — stays identical no matter which signature version is in play.
 */
module standardwebhooks.internal;

import std.base64 : Base64;
import std.conv : to;
import std.datetime.systime : Clock;
import std.datetime.timezone : UTC;
import std.string : indexOf;

import standardwebhooks.exception;

@safe:
package:

/// Builds the canonical signed content `{msgId}.{timestamp}.{payload}`. The
/// timestamp is used verbatim as the caller's string, so a sender's exact
/// formatting round-trips through verification.
char[] buildSignedContent(scope const(char)[] msgId, scope const(char)[] tsStr,
		scope const(char)[] payload)
{
	return msgId ~ "." ~ tsStr ~ "." ~ payload;
}

/// Current unix time in seconds, in UTC.
long currentUnixSeconds()
{
	return Clock.currTime(UTC()).toUnixTime();
}

/// ASCII case-insensitive equality. Header names are guaranteed ASCII, so an
/// allocation-free byte-wise fold suffices and avoids the throwaway GC string
/// per key that `std.string.toLower` would produce on every lookup.
bool asciiEqualCI(scope const(char)[] a, scope const(char)[] b) @nogc nothrow pure
{
	if (a.length != b.length)
		return false;
	foreach (i; 0 .. a.length)
	{
		char ca = a[i];
		char cb = b[i];
		// Fold the uppercase range onto lowercase before comparing.
		if (ca >= 'A' && ca <= 'Z')
			ca += 'a' - 'A';
		if (cb >= 'A' && cb <= 'Z')
			cb += 'a' - 'A';
		if (ca != cb)
			return false;
	}
	return true;
}

/// The canonical Standard Webhooks header carrying the unique message id.
enum string wireHeaderId = "webhook-id";
/// The canonical Standard Webhooks header carrying the unix-seconds timestamp.
enum string wireHeaderTimestamp = "webhook-timestamp";
/// The canonical Standard Webhooks header carrying the space-delimited signatures.
enum string wireHeaderSignature = "webhook-signature";

/// The Svix-branded header aliases, accepted as a fallback so payloads from a
/// Svix sender verify unchanged. They stay package-private: surfacing them as
/// public API would promote an interop fallback to first-class and undercut the
/// canonical `webhook-*` names. Each verify passes the matching canonical name
/// ahead of its alias to `lookupHeader`, so the canonical value wins when both
/// are present.
enum string svixHeaderId = "svix-id";
enum string svixHeaderTimestamp = "svix-timestamp"; /// ditto
enum string svixHeaderSignature = "svix-signature"; /// ditto

/// Case-insensitive lookup returning the value for the first of `names` (which
/// must be lowercase) that is present, or `null` if none is. `names` is scanned
/// in priority order, so callers pass the canonical `webhook-*` name ahead of
/// its Svix-branded `svix-*` alias and the canonical value wins whenever both
/// headers are present.
string lookupHeader(in string[string] headers, scope const(string)[] names...)
{
	foreach (name; names)
		foreach (key, value; headers)
			if (asciiEqualCI(key, name))
				return value;
	return null;
}

/// Runs the non-crypto preamble shared by both verification schemes: looks up
/// the three required headers (canonical name then Svix alias), rejects a
/// missing one, and — when `checkTimestamp` is set — tolerance-checks the
/// timestamp against `now`. The looked-up header values are returned through the
/// `out` parameters so each scheme can build and check its own signature once.
///
/// Throws: $(REF WebhookVerificationException, standardwebhooks,exception) with
///   `missingHeaders` if any required header is absent, or the timestamp errors
///   raised by $(LREF verifyTimestamp).
void requireHeaders(in string[string] headers, long now, bool checkTimestamp,
		long toleranceSeconds, out const(char)[] msgId, out const(char)[] tsHeader,
		out const(char)[] sigHeader)
{
	msgId = lookupHeader(headers, wireHeaderId, svixHeaderId);
	tsHeader = lookupHeader(headers, wireHeaderTimestamp, svixHeaderTimestamp);
	sigHeader = lookupHeader(headers, wireHeaderSignature, svixHeaderSignature);

	if (msgId.length == 0 || tsHeader.length == 0 || sigHeader.length == 0)
		throw new WebhookVerificationException("Missing required headers",
				WebhookError.missingHeaders);

	if (checkTimestamp)
		verifyTimestamp(tsHeader, now, toleranceSeconds);
}

/// Parses and tolerance-checks a timestamp header against `now`.
///
/// Throws: $(REF WebhookVerificationException, standardwebhooks,exception) with
///   `invalidTolerance` if `toleranceSeconds` is not positive, `invalidHeaders`
///   if `tsHeader` is not an integer, `timestampTooOld` if it precedes the
///   window, or `timestampTooNew` if it follows the window.
void verifyTimestamp(scope const(char)[] tsHeader, long now, long toleranceSeconds)
{
	// A non-positive tolerance admits no timestamp at all, so every message
	// would otherwise be rejected as too old; surface the misconfiguration
	// distinctly instead of masking it as a routine stale-timestamp rejection.
	if (toleranceSeconds <= 0)
		throw new WebhookVerificationException("Invalid tolerance", WebhookError.invalidTolerance);

	long ts;
	// A non-numeric value raises ConvException and invalid UTF-8 bytes raise
	// UTFException; both mean the header is unparseable, so map any parse failure
	// to invalidHeaders.
	try
		ts = tsHeader.to!long;
	catch (Exception)
		throw new WebhookVerificationException("Invalid Signature Headers",
				WebhookError.invalidHeaders);

	// Unix seconds are never negative for any real sender; rejecting them up
	// front keeps the `now - ts` / `ts - now` differences below from wrapping
	// for a pathological near-`long.min` value, which would silently bypass the
	// window. A negative timestamp is necessarily far before any plausible now.
	if (ts < 0)
		throw new WebhookVerificationException("Message timestamp too old",
				WebhookError.timestampTooOld);

	if (now - ts > toleranceSeconds)
		throw new WebhookVerificationException("Message timestamp too old",
				WebhookError.timestampTooOld);
	if (ts - now > toleranceSeconds)
		throw new WebhookVerificationException("Message timestamp too new",
				WebhookError.timestampTooNew);
}

/// Upper bound on the number of space-delimited entries `anySignature` examines.
/// Each examined entry can trigger a full HMAC/ed25519 verify, so capping the
/// count bounds the work an attacker can force with a long header and keeps the
/// limit comfortably above any realistic key-rotation overlap. Capping at 64 is
/// an intentional anti-amplification divergence from the reference libraries,
/// which examine every entry; signature entries beyond the cap are not examined.
enum size_t maxSignatureEntries = 64;

/// Walks the space-delimited `webhook-signature` header, splitting each entry on
/// its first comma into a `(version, signature)` pair, and returns true as soon
/// as `pred` accepts one. Entries without a comma are skipped (not errored),
/// matching every reference library. Scanning stops once `maxSignatureEntries`
/// entries have been examined, after which the remainder is treated as no-match.
bool anySignature(scope const(char)[] sigHeader,
		scope bool delegate(scope const(char)[] version_, scope const(char)[] signature) @safe pred)
{
	size_t start = 0;
	size_t examined = 0;
	while (start <= sigHeader.length)
	{
		if (examined >= maxSignatureEntries)
			break;

		const end = sigHeader.indexOf(' ', start);
		const part = end < 0 ? sigHeader[start .. $] : sigHeader[start .. end];
		++examined;

		const comma = part.indexOf(',');
		if (comma >= 0 && pred(part[0 .. comma], part[comma + 1 .. $]))
			return true;

		if (end < 0)
			break;
		start = end + 1;
	}
	return false;
}

/// Pads `s` to a base64 boundary with `=` and standard-base64 decodes it.
/// Tolerating missing padding lets callers accept values whose trailing `=`
/// were stripped.
///
/// Throws: `Exception` if `s` is not valid base64.
immutable(ubyte)[] decodeStdBase64(scope const(char)[] s)
{
	auto padded = s.dup;
	while (padded.length % 4 != 0)
		padded ~= '=';

	// Base64.decode asserts (an uncatchable Error) on malformed input such as a
	// '=' that is not trailing padding, so the input is validated up front and a
	// plain Exception is thrown instead. This keeps the catch(Exception) at the
	// call sites effective and behaves identically in debug and -release.
	if (!isWellFormedStdBase64(padded))
		throw new Exception("Invalid base64");

	return Base64.decode(padded).idup;
}

/// True when `s` is well-formed, fully-padded standard base64: its length is a
/// multiple of four, every character is in the standard alphabet (or a trailing
/// `=`), and any `=` appears only as the final one or two characters.
bool isWellFormedStdBase64(scope const(char)[] s) @safe @nogc nothrow pure
{
	if (s.length % 4 != 0)
		return false;

	size_t pad = 0;
	foreach (c; s)
	{
		if (c == '=')
			++pad;
		else
		{
			// A non-padding character after padding has begun is malformed.
			if (pad != 0)
				return false;
			const isAlnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
			if (!(isAlnum || c == '+' || c == '/'))
				return false;
		}
	}

	// Standard base64 never needs more than two padding characters.
	return pad <= 2;
}

/// Strips `prefix` from `value` (if present) and base64-decodes the remainder to
/// raw key bytes.
///
/// Throws: $(REF WebhookVerificationException, standardwebhooks,exception) with
///   `emptySecret` for an empty `value`, or `invalidSecret` if the remainder is
///   not valid base64.
immutable(ubyte)[] decodePrefixedKey(string value, string prefix)
{
	if (value.length == 0)
		throw new WebhookVerificationException("Secret can't be empty.", WebhookError.emptySecret);

	auto b64 = value;
	if (b64.length >= prefix.length && b64[0 .. prefix.length] == prefix)
		b64 = b64[prefix.length .. $];

	try
		return decodeStdBase64(b64);
	catch (Exception)
		throw new WebhookVerificationException("Invalid secret", WebhookError.invalidSecret);
}

// --- Tests ---

@safe unittest
{
	// The ASCII fold compares without allocating, so it is callable in a
	// `@nogc nothrow` context.
	static assert(__traits(compiles, () @nogc nothrow{
			cast(void) asciiEqualCI("a", "A");
		}));
}

@safe @nogc nothrow unittest
{
	// Differing case on each side still matches.
	assert(asciiEqualCI("Webhook-Id", "webhook-id"));
}

@safe @nogc nothrow unittest
{
	// Distinct names do not match.
	assert(!asciiEqualCI("webhook-id", "webhook-timestamp"));
}

@safe @nogc nothrow unittest
{
	// Differing length never matches.
	assert(!asciiEqualCI("abc", "abcd"));
}

@safe @nogc nothrow unittest
{
	// Bytes outside the ASCII-letter range fold to themselves.
	assert(asciiEqualCI("x-1_2", "X-1_2"));
	assert(!asciiEqualCI("[", "{"));
}

@safe unittest
{
	// requireHeaders returns the looked-up values through its out parameters.
	string[string] headers = [
		"webhook-id": "msg_1", "webhook-timestamp": "100",
		"webhook-signature": "v1,AAAA"
	];
	const(char)[] msgId, tsHeader, sigHeader;
	requireHeaders(headers, 100, true, 300, msgId, tsHeader, sigHeader);
	assert(msgId == "msg_1");
	assert(tsHeader == "100");
	assert(sigHeader == "v1,AAAA");
}

@safe unittest
{
	// requireHeaders accepts the Svix-branded aliases as a fallback.
	string[string] headers = [
		"svix-id": "msg_2", "svix-timestamp": "200", "svix-signature": "v1,BBBB"
	];
	const(char)[] msgId, tsHeader, sigHeader;
	requireHeaders(headers, 200, true, 300, msgId, tsHeader, sigHeader);
	assert(msgId == "msg_2");
	assert(tsHeader == "200");
	assert(sigHeader == "v1,BBBB");
}

@safe unittest
{
	import std.exception : collectException;

	// A zero tolerance is a configuration error, reported distinctly rather than
	// as a stale-timestamp rejection of an otherwise-current timestamp.
	auto ex = collectException!WebhookVerificationException(verifyTimestamp("1000", 1000, 0));
	assert(ex !is null && ex.error == WebhookError.invalidTolerance);
}

@safe unittest
{
	// Lookup matches header keys case-insensitively, in `names` priority order.
	string[string] headers = ["Webhook-Id": "canonical", "Svix-Id": "alias"];
	assert(lookupHeader(headers, "webhook-id", "svix-id") == "canonical");
}

@safe unittest
{
	import std.exception : collectException;

	// A missing required header is reported as missingHeaders.
	string[string] headers = ["webhook-id": "msg_3", "webhook-timestamp": "300"];
	const(char)[] msgId, tsHeader, sigHeader;
	auto ex = collectException!WebhookVerificationException(requireHeaders(headers,
			300, true, 300, msgId, tsHeader, sigHeader));
	assert(ex !is null);
	assert(ex.error == WebhookError.missingHeaders);
}

@safe unittest
{
	import std.exception : collectException;

	// A negative tolerance is likewise surfaced as invalidTolerance.
	auto ex = collectException!WebhookVerificationException(verifyTimestamp("1000", 1000, -5));
	assert(ex !is null && ex.error == WebhookError.invalidTolerance);
}

@safe unittest
{
	import std.exception : collectException;

	// requireHeaders tolerance-checks the timestamp when checkTimestamp is set.
	string[string] headers = [
		"webhook-id": "msg_4", "webhook-timestamp": "100",
		"webhook-signature": "v1,AAAA"
	];
	const(char)[] msgId, tsHeader, sigHeader;
	auto ex = collectException!WebhookVerificationException(requireHeaders(headers,
			100_000, true, 300, msgId, tsHeader, sigHeader));
	assert(ex !is null);
	assert(ex.error == WebhookError.timestampTooOld);
}

@safe unittest
{
	// Falls back to the aliased name when the canonical one is absent.
	string[string] headers = ["SVIX-ID": "alias"];
	assert(lookupHeader(headers, "webhook-id", "svix-id") == "alias");
}

@safe unittest
{
	// No matching header yields null.
	string[string] headers = ["content-type": "application/json"];
	assert(lookupHeader(headers, "webhook-id", "svix-id") is null);
}

@safe unittest
{
	import std.exception : collectException;

	// The tolerance check precedes header parsing, so a non-positive tolerance is
	// reported even when the timestamp header is itself unparseable.
	auto ex = collectException!WebhookVerificationException(verifyTimestamp("oops", 1000, 0));
	assert(ex !is null && ex.error == WebhookError.invalidTolerance);
}

@safe unittest
{
	// A far-out-of-window timestamp is accepted when checkTimestamp is false.
	string[string] headers = [
		"webhook-id": "msg_5", "webhook-timestamp": "100",
		"webhook-signature": "v1,AAAA"
	];
	const(char)[] msgId, tsHeader, sigHeader;
	requireHeaders(headers, 100_000, false, 300, msgId, tsHeader, sigHeader);
	assert(tsHeader == "100");
}

@safe unittest
{
	import std.exception : assertThrown;

	// A '=' that is not final padding makes Base64.decode assert; it must be
	// rejected as a catchable Exception instead.
	assertThrown!Exception(decodeStdBase64("AA=AAAAA"));
}

@safe unittest
{
	import std.exception : assertThrown;

	assertThrown!Exception(decodeStdBase64("Zg==Zg=="));
}

@safe unittest
{
	import std.exception : assertThrown;

	assertThrown!Exception(decodeStdBase64("ab=cdefg"));
}

@safe unittest
{
	// Padded standard base64 round-trips.
	assert(decodeStdBase64("Zm9v") == cast(immutable(ubyte)[]) "foo");
}

@safe unittest
{
	// Unpadded input (trailing '=' stripped by the sender) still decodes.
	assert(decodeStdBase64("Zg") == cast(immutable(ubyte)[]) "f");
}

@safe unittest
{
	// Explicitly padded input decodes to the same bytes as its unpadded form.
	assert(decodeStdBase64("Zm8=") == cast(immutable(ubyte)[]) "fo");
}

@safe unittest
{
	// The leaf predicate is callable in a pure nothrow @nogc context.
	static bool callInRestrictedContext() @safe @nogc nothrow pure
	{
		return isWellFormedStdBase64("Zm9v");
	}

	assert(__traits(compiles, callInRestrictedContext()));
	assert(callInRestrictedContext());
}

@safe unittest
{
	// The svix-* aliases are the lowercase Svix-branded header names.
	assert(svixHeaderId == "svix-id");
	assert(svixHeaderTimestamp == "svix-timestamp");
	assert(svixHeaderSignature == "svix-signature");
}
