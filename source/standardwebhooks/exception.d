/**
 * Error type raised by Standard Webhooks signing and verification.
 *
 * A single exception class carries a machine-readable $(LREF WebhookError) cause
 * alongside the human-readable message, mirroring the Python and JavaScript
 * reference libraries (one exception type) while still allowing typed handling
 * the way the Rust reference library does (an enum of causes).
 */
module standardwebhooks.exception;

@safe:

/// The reason a signing or verification operation failed.
enum WebhookError
{
	/// One of `webhook-id`, `webhook-timestamp` or `webhook-signature` was
	/// absent or empty.
	missingHeaders,
	/// A header was present but malformed (e.g. a non-numeric timestamp).
	invalidHeaders,
	/// `now - timestamp` exceeded the tolerance window.
	timestampTooOld,
	/// `timestamp - now` exceeded the tolerance window.
	timestampTooNew,
	/// No `v1` signature in the header matched the expected signature.
	noMatch,
	/// The secret was not valid base64.
	invalidSecret,
	/// The secret string was empty.
	emptySecret,
	/// A signing operation was attempted with an asymmetric verify-only key
	/// (a `whpk_` public key); a `whsk_` signing key is required to sign.
	signingKeyRequired,
}

/// Thrown by `Webhook.verify` (and the constructor, for a bad secret) when an
/// operation cannot complete. The `error` field identifies the cause so callers
/// can branch without parsing `msg`.
class WebhookVerificationException : Exception
{
	/// The machine-readable cause of the failure.
	WebhookError error;

	///
	this(string msg, WebhookError error = WebhookError.noMatch,
			string file = __FILE__, size_t line = __LINE__) pure nothrow @safe
	{
		super(msg, file, line);
		this.error = error;
	}
}
