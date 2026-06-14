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

extern (C) @system @nogc nothrow
{
	/// Initialises the library; safe and idempotent. Must be called before other
	/// functions in multithreaded programs. Returns 0 on success, 1 if already
	/// initialised, and a negative value on failure.
	int sodium_init();

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

	/// Overwrites `len` bytes at `pnt` with zeros in a way the compiler will not
	/// optimise away, used to wipe transient secret material before it leaves scope.
	void sodium_memzero(scope void* pnt, size_t len);
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
/// Throws: $(REF WebhookException, standardwebhooks,exception) with
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
			throw new WebhookException("libsodium initialisation failed",
					WebhookError.cryptoFailure);
		atomicStore!(MemoryOrder.rel)(sodiumInitialised, true);
	}
}
