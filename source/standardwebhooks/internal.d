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
import std.conv : to, ConvException;
import std.datetime.systime : Clock;
import std.datetime.timezone : UTC;
import std.string : indexOf, toLower;

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

/// Case-insensitive lookup returning the value for the first of `names` (which
/// must be lowercase) that is present, or `null` if none is. `names` is scanned
/// in priority order, so callers pass the canonical `webhook-*` name ahead of
/// its Svix-branded `svix-*` alias and the canonical value wins whenever both
/// headers are present.
string lookupHeader(in string[string] headers, scope const(string)[] names...)
{
	foreach (name; names)
		foreach (key, value; headers)
			if (key.toLower == name)
				return value;
	return null;
}

/// Parses and tolerance-checks a timestamp header against `now`.
///
/// Throws: $(REF WebhookVerificationException, standardwebhooks,exception) with
///   `invalidHeaders` if `tsHeader` is not an integer, `timestampTooOld` if it
///   precedes the window, or `timestampTooNew` if it follows the window.
void verifyTimestamp(scope const(char)[] tsHeader, long now, long toleranceSeconds)
{
	long ts;
	try
		ts = tsHeader.to!long;
	catch (ConvException)
		throw new WebhookVerificationException("Invalid Signature Headers",
				WebhookError.invalidHeaders);

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
/// limit comfortably above any realistic key-rotation overlap.
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
	return Base64.decode(padded).idup;
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
