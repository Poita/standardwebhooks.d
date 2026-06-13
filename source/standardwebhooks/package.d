/**
 * standardwebhooks — a $(LINK2 https://www.standardwebhooks.com/, Standard
 * Webhooks) implementation for D.
 *
 * Importing `standardwebhooks` re-exports the full public API: the
 * $(REF Webhook, standardwebhooks,webhook) signer/verifier, the canonical
 * header-name constants, and the
 * $(REF WebhookVerificationException, standardwebhooks,exception) error type.
 *
 * The core has no third-party dependencies. For vibe.d HTTP integration, depend
 * on the `standardwebhooks:vibe` subpackage and `import standardwebhooks.vibe;`.
 */
module standardwebhooks;

public import standardwebhooks.webhook;
public import standardwebhooks.exception;
