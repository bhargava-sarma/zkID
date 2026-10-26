// The part of ffjavascript (a snarkjs dependency, no bundled types) the tests use.
declare module 'ffjavascript' {
  export function buildBn128(singleThread?: boolean): Promise<any>;
  export const utils: {
    stringifyBigInts(value: unknown): any;
    unstringifyBigInts(value: unknown): any;
  };
}
