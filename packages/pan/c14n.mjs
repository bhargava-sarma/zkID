// Exclusive XML canonicalization (without comments) of a DigiLocker record's
// <Certificate> element with its <Signature> removed: the bytes whose SHA-256
// DigiLocker signs. Only what such a record holds is supported: elements and
// attributes without namespaces, text, CDATA and comments (which are dropped).
// Anything else throws a C14nError rather than produce bytes the signature
// would not match. test/c14n.test.mjs checks it against xml-crypto.

export class C14nError extends Error {
  constructor(message) {
    super(message);
    this.name = 'C14nError';
  }
}

const ELEMENT = 1;
const TEXT = 3;
const CDATA = 4;
const COMMENT = 8;

const text = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
const attribute = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');

export function canonicalize(element) {
  const out = [];
  const visit = (node) => {
    if (node.nodeType === ELEMENT) {
      if (node.namespaceURI || node.prefix) throw new C14nError(`<${node.nodeName}> is in a namespace`);
      const attrs = Array.from(node.attributes, (a) => {
        if (a.namespaceURI || a.prefix || a.name === 'xmlns') throw new C14nError(`<${node.nodeName}> has a namespaced attribute ${a.name}`);
        return [a.name, a.value];
      }).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      out.push(`<${node.nodeName}`);
      for (const [name, value] of attrs) out.push(` ${name}="${attribute(value)}"`);
      out.push('>');
      for (const child of Array.from(node.childNodes)) visit(child);
      out.push(`</${node.nodeName}>`);
    } else if (node.nodeType === TEXT || node.nodeType === CDATA) {
      out.push(text(node.nodeValue));
    } else if (node.nodeType !== COMMENT) {
      throw new C14nError(`unsupported node of type ${node.nodeType} in the record`);
    }
  };
  visit(element);
  return out.join('');
}
