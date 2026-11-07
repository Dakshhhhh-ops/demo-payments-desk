// TLS settings for the public API.
// Used when the service runs on its own. In production, TLS for the public
// API is terminated at the acquirer's edge gateway (see infra/DEPLOY.md).
export const tlsOptions = {
  minVersion: 'TLSv1.2',
  ecdhCurve: 'prime256v1',
  ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
};
