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
import vibe.stream.operations : readAll;

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
	// Read the raw body bytes: signature verification must run over the exact
	// bytes received. UTF-8 validation or BOM stripping would alter them.
	const payload = () @trusted { return cast(string) req.bodyReader.readAll(); }();
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
/// On duplicate keys the last field in insertion order wins, so the result is
/// deterministic.
package string[string] toAA(in InetHeaderMap headers) @safe
{
	string[string] result;
	foreach (key, value; headers.byKeyValue)
		result[key] = value;
	return result;
}

/// toAA copies every field of the header map into the plain AA.
@safe unittest
{
	InetHeaderMap headers;
	headers.addField(headerId, "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W");
	headers.addField(headerTimestamp, "1614265330");
	headers.addField(headerSignature, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJ");

	auto aa = toAA(headers);
	assert(aa[headerId] == "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W");
	assert(aa[headerTimestamp] == "1614265330");
	assert(aa[headerSignature] == "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJ");
}

/// toAA preserves the original key casing; the core verifier matches headers
/// case-insensitively, so mixed-case keys still resolve.
@safe unittest
{
	InetHeaderMap headers;
	headers.addField("Webhook-Id", "msg_abc");

	auto aa = toAA(headers);
	assert("Webhook-Id" in aa);
	assert(aa["Webhook-Id"] == "msg_abc");
}

/// On a duplicate key the last field in insertion order wins deterministically.
@safe unittest
{
	InetHeaderMap headers;
	headers.addField(headerId, "first");
	headers.addField(headerId, "second");

	auto aa = toAA(headers);
	assert(aa[headerId] == "second");
}

/// A signature produced by the core signer verifies against the AA that toAA
/// builds from the equivalent header map, mirroring verifyRequest end to end.
@safe unittest
{
	import std.conv : to;

	auto wh = Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
	enum msgId = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W";
	enum timestamp = 1_614_265_330L;
	enum payload = `{"event":"ping"}`;

	const signature = wh.sign(msgId, timestamp, payload);

	InetHeaderMap headers;
	headers.addField(headerId, msgId);
	headers.addField(headerTimestamp, timestamp.to!string);
	headers.addField(headerSignature, signature);

	assert(wh.verifyIgnoringTimestamp(payload, toAA(headers)) == payload);
}
