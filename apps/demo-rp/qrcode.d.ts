// The part of qrcode's API that server.ts uses (the package ships no types).
declare module 'qrcode' {
  export function toDataURL(text: string, options?: { errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H'; margin?: number; scale?: number }): Promise<string>;
}
