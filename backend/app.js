// v2 has no backend that receives credentials: the holder app proves in the
// browser and sends proofs only to the verifier that asked (apps/demo-rp). The
// v1 upload, OCR, signing and server-side proving endpoints are removed; v1 is
// preserved at tag v1-mock-issuer-demo. This keeps the deployment's /api route.
const express = require('express');

const app = express();

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', note: 'zkID v2 has no credential-handling backend.', timestamp: new Date().toISOString() });
});

module.exports = app;
