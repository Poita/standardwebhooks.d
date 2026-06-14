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
 *     catch (WebhookException)
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
 * `Wh` is any verifier exposing a `verify(payload, headers)` method, so both the
 * symmetric $(REF Webhook, standardwebhooks,webhook) and the asymmetric
 * $(REF AsymmetricWebhook, standardwebhooks,ed25519) bind. Lazy template
 * instantiation keeps this subpackage free of any dependency on `:ed25519`.
 *
 * Returns: the verified raw payload (the request body), ready to parse.
 *
 * Throws: $(REF WebhookException, standardwebhooks,exception) if the
 *   request is missing headers or the signature/timestamp does not verify.
 */
string verifyRequest(Wh)(in Wh wh, scope HTTPServerRequest req) @safe
{
	// Read the raw body bytes: signature verification must run over the exact
	// bytes received. UTF-8 validation or BOM stripping would alter them.
	string payload = () @trusted { return cast(string) req.bodyReader.readAll(); }();
	// The body buffer is owned here, so verifying for its throwing side-effect
	// and returning the payload as `string` avoids a copy at the receiver.
	wh.verify(payload, toAA(req.headers));
	return payload;
}

/// verifyRequest returns an owned `string`, not a borrowed `const(char)[]`.
@safe unittest
{
	import std.traits : ReturnType;

	static assert(is(ReturnType!(verifyRequest!Webhook) == string));
}

/**
 * Signs `payload` and sets the `webhook-id`, `webhook-timestamp` and
 * `webhook-signature` headers on `req`. Does not write the body; send `payload`
 * as the request body yourself so the bytes signed match the bytes sent.
 *
 * `Wh` is any signer exposing a `sign(msgId, timestamp, payload)` method, so both
 * the symmetric $(REF Webhook, standardwebhooks,webhook) and the asymmetric
 * $(REF AsymmetricWebhook, standardwebhooks,ed25519) bind without this subpackage
 * depending on `:ed25519`.
 */
void signRequest(Wh)(in Wh wh, scope HTTPClientRequest req, string msgId,
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

version (unittest)
{
	/// A stand-in for the asymmetric `AsymmetricWebhook`: it exposes the same
	/// `verify`/`sign` shape the templated helpers bind to, so the `:vibe` bridge
	/// works for asymmetric verifiers without this subpackage depending on
	/// `:ed25519`.
	private struct FakeAsymmetricWebhook
	{
		const(char)[] verify(scope return const(char)[] payload, in string[string] headers) const @safe
		{
			return payload;
		}

		string sign(string msgId, long timestamp, scope const(char)[] payload) const @safe
		{
			return "v1a,fake";
		}
	}
}

/// The templated helpers bind to any verifier/signer exposing the asymmetric
/// `verify`/`sign` shape, so `:ed25519`'s `AsymmetricWebhook` gets the bridge
/// without `:vibe` depending on `:ed25519`.
@safe unittest
{
	static assert(__traits(compiles, verifyRequest(FakeAsymmetricWebhook.init,
			HTTPServerRequest.init)));
	static assert(__traits(compiles, signRequest(FakeAsymmetricWebhook.init,
			HTTPClientRequest.init, "msg_1", 1_614_265_330L, `{"event":"ping"}`)));
}
