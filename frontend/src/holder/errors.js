// Every failure in the holder app has a code and a message a person can act on.
export class HolderError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'HolderError';
    this.code = code;
  }
}
