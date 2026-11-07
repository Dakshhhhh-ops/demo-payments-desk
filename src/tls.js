// TLS settings for the public API.
// Used when the service runs on its own (local and staging runs). In
// production, TLS for the public API is terminated at the acquirer's edge
// gateway (see infra/DEPLOY.md), so these settings do not reach real clients;
// that side needs a change request with the acquirer's platform team.
//
// Key exchange: hybrid X25519 + ML-KEM-768 (X25519MLKEM768, FIPS 203) is
// offered first, with classical X25519 as the fallback. prime256v1 is no
// longer offered. X25519MLKEM768 needs OpenSSL 3.5+ (Node 24.7+).
// TLS 1.3 only: nothing connects to local or staging over TLS 1.2.
export const tlsOptions = {
  minVersion: 'TLSv1.3',
  ecdhCurve: 'X25519MLKEM768:X25519',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
};
