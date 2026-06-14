/**
 * A minimal `extern(C)` binding to the handful of libsodium `crypto_sign_*`
 * (ed25519) functions the asymmetric scheme needs. Kept deliberately tiny and
 * auditable rather than pulling a full binding: this is the only foreign code in
 * the subpackage.
 *
 * libsodium's detached ed25519 API maps exactly onto the Standard Webhooks key
 * formats — a `whsk_` signing key decodes to libsodium's 64-byte secret key
 * (`seed ‖ public_key`) and a `whpk_` public key decodes to its 32-byte public
 * key — so the decoded bytes are passed straight through with no reshaping.
 *
 * The system libsodium shared library is linked via the subpackage `dub.json`
 * (`libs`/`lflags`). $(LREF ensureSodiumInitialised) performs the one-time
 * `sodium_init()` on first use rather than at module load, so merely linking the
 * subpackage cannot abort the process.
 */
module standardwebhooks.sodium;

import core.atomic;

import standardwebhooks.exception;

/// Length in bytes of a detached ed25519 signature (`crypto_sign_BYTES`).
enum size_t signatureBytes = 64;
/// Length in bytes of an ed25519 public key (`crypto_sign_PUBLICKEYBYTES`).
enum size_t publicKeyBytes = 32;
/// Length in bytes of a libsodium ed25519 secret key (`crypto_sign_SECRETKEYBYTES`),
/// which is `seed ‖ public_key`.
enum size_t secretKeyBytes = 64;
/// Length in bytes of an ed25519 seed (`crypto_sign_SEEDBYTES`).
enum size_t seedBytes = 32;

/// Minimum libsodium SONAME major version (`sodium_library_version_major()`)
/// this binding is verified against. libsodium reports `10` for the 1.0.x
/// series, where the detached ed25519 API used here is stable.
enum int minLibsodiumVersionMajor = 9;

extern (C) @system @nogc nothrow
{
	/// Initialises the library; safe and idempotent. Must be called before other
	/// functions in multithreaded programs. Returns 0 on success, 1 if already
	/// initialised, and a negative value on failure.
	int sodium_init();

	/// Returns the runtime SONAME major version of the linked libsodium. Used to
	/// reject a shared library older than the detached ed25519 API relied on here.
	int sodium_library_version_major();

	/// Returns the human-readable runtime version string of the linked libsodium
	/// (e.g. `"1.0.18"`).
	const(char)* sodium_version_string();

	/// Writes a detached signature of `m[0 .. mlen]` under secret key `sk` (64
	/// bytes) into `sig` (64 bytes); stores the length in `*siglen_p` if non-null.
	/// Returns 0 on success.
	int crypto_sign_detached(scope ubyte* sig, scope ulong* siglen_p,
			scope const(ubyte)* m, ulong mlen, scope const(ubyte)* sk);

	/// Verifies detached signature `sig` (64 bytes) over `m[0 .. mlen]` against
	/// public key `pk` (32 bytes). Returns 0 if the signature is valid, -1
	/// otherwise.
	int crypto_sign_verify_detached(scope const(ubyte)* sig,
			scope const(ubyte)* m, ulong mlen, scope const(ubyte)* pk);

	/// Derives a key pair from a 32-byte `seed`, writing the 32-byte public key to
	/// `pk` and the 64-byte secret key to `sk`. Returns 0 on success.
	int crypto_sign_seed_keypair(scope ubyte* pk, scope ubyte* sk, scope const(ubyte)* seed);
}

/// Whether `sodium_init()` has already completed successfully. Written under
/// `synchronized` on its first transition with a release store, and read with an
/// acquire load on the lock-free hot path, so concurrent first callers race
/// safely and a thread that observes it set also observes the finished init.
private shared bool sodiumInitialised;

/// Performs libsodium's one-time `sodium_init()` before the first crypto call.
/// `sodium_init()` is itself idempotent, but gating on a flag keeps the common
/// case lock-free. A negative return value means the library could not
/// initialise and no signing is safe.
///
/// Throws: $(REF WebhookVerificationException, standardwebhooks,exception) with
///   `cryptoFailure` if `sodium_init()` fails.
void ensureSodiumInitialised() @trusted
{
	// Acquire load pairs with the release store below so a thread that sees the
	// flag set also sees the completed initialisation.
	if (atomicLoad!(MemoryOrder.acq)(sodiumInitialised))
		return;

	synchronized
	{
		if (atomicLoad!(MemoryOrder.acq)(sodiumInitialised))
			return;
		if (sodium_init() < 0)
			throw new WebhookVerificationException("libsodium initialisation failed",
					WebhookError.cryptoFailure);
		checkSodiumVersion();
		atomicStore!(MemoryOrder.rel)(sodiumInitialised, true);
	}
}

/// Rejects a linked libsodium too old to provide the detached ed25519 API this
/// binding calls, so an incompatible shared library fails loudly at first use
/// rather than mis-signing or crashing.
///
/// Throws: $(REF WebhookVerificationException, standardwebhooks,exception) with
///   `invalidSecret` if the runtime version is below $(LREF minLibsodiumVersionMajor).
private void checkSodiumVersion() @trusted
{
	if (sodium_library_version_major() < minLibsodiumVersionMajor)
		throw new WebhookVerificationException("linked libsodium is too old; "
				~ "version 1.0.4 or newer is required", WebhookError.invalidSecret);
}

/// The runtime version string of the linked libsodium (e.g. `"1.0.18"`),
/// exposed for diagnostics and compatibility checks.
string libsodiumVersion() @trusted
{
	import std.string : fromStringz;

	return sodium_version_string().fromStringz.idup;
}

@safe unittest
{
	// The linked libsodium reports a non-empty, dotted runtime version.
	import std.algorithm : canFind;

	const v = libsodiumVersion();
	assert(v.length > 0);
	assert(v.canFind('.'));
}
