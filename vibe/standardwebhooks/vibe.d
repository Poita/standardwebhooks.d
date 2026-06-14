/**
 * vibe.d HTTP integration for Standard Webhooks.
 *
 * These helpers bridge a $(REF Webhook, standardwebhooks,webhook) to vibe.d's
 * HTTP types: verify an inbound `HTTPServerRequest` in one call, or sign and
 * attach the Standard Webhooks headers to an outbound `HTTPClientRequest`.
 *
 * This module lives in the `standardwebhooks:vibe` subpackage so the core
 * library stays dependency-free. Depend on it explicitly:
 * ---
 * "dependencies": { "standardwebhooks:vibe": "~>0.1" }
 * ---
 *
 * Example (receiver):
 * ---
 * import standardwebhooks;
 * import standardwebhooks.vibe;
 *
 * void handler(HTTPServerRequest req, HTTPServerResponse res)
 * {
 *     auto wh = Webhook("whsec_...");
 *     try
 *     {
 *         auto payload = wh.verifyRequest(req);
 *         // payload is the verified raw body; safe to parse and act on.
 *         res.writeBody("ok");
 *     }
 *     catch (WebhookVerificationException)
 *     {
 *         res.statusCode = 400;
 *         res.writeBody("invalid signature");
 *     }
 * }
 * ---
 */
module standardwebhooks.vibe;

import vibe.http.client : HTTPClientRequest;
import vibe.http.server : HTTPServerRequest;
import vibe.inet.message : InetHeaderMap;
import vibe.stream.operations : readAllUTF8;

import standardwebhooks;

/**
 * Reads the raw body of `req`, extracts the Standard Webhooks headers, and
 * verifies the signature and timestamp.
 *
 * Returns: the verified raw payload (the request body), ready to parse.
 *
 * Throws: $(REF WebhookVerificationException, standardwebhooks,exception) if the
 *   request is missing headers or the signature/timestamp does not verify.
 */
const(char)[] verifyRequest(in Webhook wh, scope HTTPServerRequest req) @safe
{
	const payload = () @trusted { return req.bodyReader.readAllUTF8(); }();
	return wh.verify(payload, toAA(req.headers));
}

/**
 * Signs `payload` and sets the `webhook-id`, `webhook-timestamp` and
 * `webhook-signature` headers on `req`. Does not write the body; send `payload`
 * as the request body yourself so the bytes signed match the bytes sent.
 */
void signRequest(in Webhook wh, scope HTTPClientRequest req, string msgId,
		long timestamp, scope const(char)[] payload) @safe
{
	req.headers[headerId] = msgId;
	req.headers[headerTimestamp] = () @safe {
		import std.conv : to;

		return timestamp.to!string;
	}();
	req.headers[headerSignature] = wh.sign(msgId, timestamp, payload);
}

/// Copies a vibe `InetHeaderMap` (case-insensitive) into a plain associative
/// array for the core verifier, whose own lookup is also case-insensitive.
private string[string] toAA(in InetHeaderMap headers) @safe
{
	string[string] result;
	foreach (key, value; headers.byKeyValue)
		result[key] = value;
	return result;
}
