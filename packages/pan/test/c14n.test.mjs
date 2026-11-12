// c14n.mjs against xml-crypto's exclusive canonicalization: the same bytes for
// synthetic records, for values that need escaping, and, with PAN_XML=<paths
// of real records, outside git, separated by ':'>, for those (nothing of them
// is printed). Namespaced content is refused.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DOMParser } from '@xmldom/xmldom';
import { ExclusiveCanonicalization } from 'xml-crypto';
import { C14nError, canonicalize } from '../c14n.mjs';
import { makeRecord, testIssuer } from '../synthetic.mjs';

const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const issuer = testIssuer();

// The root element, without its signature, as record.mjs canonicalizes it.
function root(xml) {
  const element = new DOMParser().parseFromString(xml, 'text/xml').documentElement;
  for (const signature of Array.from(element.getElementsByTagNameNS(DSIG, 'Signature'))) signature.parentNode.removeChild(signature);
  return element;
}
const theirs = (xml) => new ExclusiveCanonicalization().process(root(xml), {}).toString();
const ours = (xml) => canonicalize(root(xml));

test('synthetic records canonicalize as xml-crypto does', async () => {
  for (const options of [{}, { gender: 'FEMALE' }, { gender: 'TRANSGENDER', name: 'A VERY LONG SYNTHETIC TEST NAME WITH MANY WORDS IN IT' }, { qr: '' }]) {
    const xml = await makeRecord(issuer, options);
    assert.equal(ours(xml), theirs(xml));
  }
});

test('values that need escaping, comments, CDATA, whitespace and non-ASCII text canonicalize as xml-crypto does', () => {
  const cases = [
    '<Certificate b="2" a="1" c=""><X/></Certificate>',
    '<Certificate name="A &amp; B &lt;C&gt; &quot;D&quot; &apos;E&apos; tab&#9;nl&#10;cr&#13;end"><P v="x&#x9;y"/></Certificate>',
    '<Certificate>text &amp; &lt;tag&gt; &#13; and &gt;</Certificate>',
    '<Certificate><!-- a comment --><A><![CDATA[raw <b> & "quotes"]]></A>\n  <B>  spaced  </B>\n</Certificate>',
    '<Certificate name="ÉLODIE ÑÚÑEZ 日本"><Q>ąčęėįšųūž → ✓</Q></Certificate>',
  ];
  for (const xml of cases) assert.equal(ours(xml), theirs(xml), xml);
});

test('namespaced elements and attributes are refused, not canonicalized', () => {
  for (const xml of ['<Certificate xmlns="urn:x"><A/></Certificate>', '<Certificate><p:A xmlns:p="urn:p"/></Certificate>', '<Certificate xmlns:p="urn:p" p:a="1"/>']) {
    assert.throws(() => ours(xml), C14nError, xml);
  }
});

test('real records, if given (PAN_XML): canonicalized as xml-crypto does', { skip: !process.env.PAN_XML && 'PAN_XML not set' }, () => {
  for (const file of process.env.PAN_XML.split(path.delimiter)) {
    const xml = fs.readFileSync(file, 'utf8');
    assert.ok(ours(xml) === theirs(xml), 'c14n.mjs differs from xml-crypto on a real record'); // no diff: it would print the record
  }
});
