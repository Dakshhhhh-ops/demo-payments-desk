# Deployment

The service runs as a container behind the acquirer's edge gateway.

- **Public API TLS** is terminated at the edge gateway, which the acquirer
  operates under their own change process. Our `src/tls.js` settings apply
  only to local and staging runs. Changing the key exchange used by real
  clients needs a change request with the acquirer's platform team.
- **Webhooks** (`src/webhooks.js`) go straight from our service to merchants.
  Some merchants verify signatures with older SDKs that only understand
  ECDSA P-256. A signature is checked once, on delivery, and is only valid
  inside the 5 minutes replay window.
  Events are dual-signed: ECDSA P-256 in `X-Signature` and ML-DSA-65
  (FIPS 204) in `X-Signature-ML-DSA-65`. `X-Signature` is kept until
  **30 June 2027**, by when every merchant SDK should verify
  `X-Signature-ML-DSA-65`; after that date we stop sending it.
  The body carries `signed_at` (Unix seconds), covered by both signatures;
  verifiers reject events older than 5 minutes or more than 60 seconds in
  the future.
- **Partner settlement files** are exchanged with the acquirer over the
  session keys from `src/session.js`. Settlement files are kept for 7 years
  under card-network rules.
- **Card vault** envelopes (`src/envelope.js`) and **customer records**
  (`src/vault.js`) are stored for the life of the customer account.
