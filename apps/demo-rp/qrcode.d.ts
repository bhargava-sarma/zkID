// The part of qrcode's API that the demo uses (the package ships no types).
declare module 'qrcode' {
  type Options = { errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H'; margin?: number; scale?: number };
  type Segments = string | { data: string; mode: 'numeric' | 'alphanumeric' | 'byte' }[];
  export function toDataURL(text: Segments, options?: Options): Promise<string>;
  export function toBuffer(text: Segments, options?: Options): Promise<Buffer>;
}
