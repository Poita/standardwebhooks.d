/**
 * A self-checking asymmetric (ed25519) Standard Webhooks example: a "sender"
 * holding an ed25519 signing key signs a payload, and a "receiver" holding only
 * the matching public key verifies it. Then we show that tampering is rejected.
 *
 * Run with `dub run --root examples/asymmetric` (requires libsodium installed).
 * It exits non-zero on any unexpected outcome, so CI uses it as a smoke test.
 */
import std.stdio : writefln, writeln;

import standardwebhooks;
import standardwebhooks.ed25519;

void main()
{
	// A fixed 32-byte seed stands in for a securely generated one. The sender
	// derives a key pair from it; the receiver only ever sees the public key.
	ubyte[32] seed = 42;
	auto signer = AsymmetricWebhook.fromSeed(seed[]);

	const id = "msg_2b3c4d5e6f";
	const timestamp = 1_614_265_330L; // unix seconds
	const payload = `{"type":"invoice.paid","data":{"id":"inv_123"}}`;

	// The sender publishes this; receivers configure it to verify.
	writefln("Public key: %s", signer.publicKeyEncoded());

	// --- Sender: build the headers to attach to the outgoing HTTP request. ---
	auto headers = signer.signHeaders(id, timestamp, payload);
	writeln("\nOutgoing headers:");
	writefln("  %s: %s", headerId, headers[headerId]);
	writefln("  %s: %s", headerTimestamp, headers[headerTimestamp]);
	writefln("  %s: %s", headerSignature, headers[headerSignature]);

	// --- Receiver: reconstruct a verify-only instance from the public key and
	// verify. The timestamp check is skipped here so the fixed historical
	// timestamp above does not trip the replay window. ---
	auto verifier = AsymmetricWebhook(signer.publicKeyEncoded());
	const verified = verifier.verifyIgnoringTimestamp(payload, headers);
	assert(verified == payload);
	writeln("\nReceiver: signature verified ✓");

	// --- A verify-only instance must not be able to sign. ---
	bool cannotSign;
	try
		verifier.sign(id, timestamp, payload);
	catch (WebhookException e)
	{
		cannotSign = true;
		writefln("Receiver: cannot forge without the signing key ✓ (%s)", e.error);
	}
	assert(cannotSign, "a public-key-only verifier should not be able to sign");

	// --- A tampered payload must NOT verify. ---
	const tampered = `{"type":"invoice.paid","data":{"id":"inv_999"}}`;
	bool rejected;
	try
		verifier.verifyIgnoringTimestamp(tampered, headers);
	catch (WebhookException e)
	{
		rejected = true;
		writefln("Receiver: tampered payload rejected ✓ (%s)", e.error);
	}
	assert(rejected, "tampered payload should have been rejected");

	writeln("\nAll checks passed.");
}
