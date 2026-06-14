/**
 * A self-checking Standard Webhooks example: a "sender" signs a payload and a
 * "receiver" verifies it, then we show that tampering is rejected.
 *
 * Run with `dub run --root examples/sign-verify`. It exits non-zero on any
 * unexpected outcome, so CI uses it as an end-to-end smoke test.
 */
import std.stdio : writefln, writeln;

import standardwebhooks;

void main()
{
	// A shared secret, as the sender and receiver would each hold.
	auto wh = Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

	const id = "msg_2b3c4d5e6f";
	const timestamp = 1_614_265_330L; // unix seconds
	const payload = `{"type":"invoice.paid","data":{"id":"inv_123"}}`;

	// --- Sender: build the headers to attach to the outgoing HTTP request. ---
	auto headers = wh.signHeaders(id, timestamp, payload);
	writeln("Outgoing headers:");
	writefln("  %s: %s", headerId, headers[headerId]);
	writefln("  %s: %s", headerTimestamp, headers[headerTimestamp]);
	writefln("  %s: %s", headerSignature, headers[headerSignature]);

	// --- Receiver: verify the request. The timestamp check is skipped here so
	// the fixed historical timestamp above does not trip the replay window. ---
	const verified = wh.verifyIgnoringTimestamp(payload, headers);
	assert(verified == payload);
	writeln("\nReceiver: signature verified ✓");

	// --- A tampered payload must NOT verify. ---
	const tampered = `{"type":"invoice.paid","data":{"id":"inv_999"}}`;
	bool rejected;
	try
		wh.verifyIgnoringTimestamp(tampered, headers);
	catch (WebhookException e)
	{
		rejected = true;
		writefln("Receiver: tampered payload rejected ✓ (%s)", e.error);
	}
	assert(rejected, "tampered payload should have been rejected");

	writeln("\nAll checks passed.");
}
