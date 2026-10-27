// Thrown for a malformed request or verifier id, on either side.
export class RequestError extends Error {
  code: 'INVALID_VERIFIER_ID' | 'INVALID_REQUEST';
  constructor(code: RequestError['code'], message: string) {
    super(`${code}: ${message}`);
    this.name = 'RequestError';
    this.code = code;
  }
}
