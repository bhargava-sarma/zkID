// The verifier's request, as this app receives it: fetched from the URL in
// ?request=, which must be on the verifier's own origin, as must the URLs it
// names (THREAT_MODEL decision 1, test T5.4). A request asking for anything
// beyond the five request fields, such as revealing more, is refused (T6.2).
import { checkRequest, nullifierSeedFor, signalHashFor } from '../../../packages/verifier-sdk/src/request.ts';
import { HolderError } from './errors.js';

const REQUEST_FIELDS = ['version', 'verifierId', 'challenge', 'maxAgeSeconds', 'expiresAt'];
const SERVED_FIELDS = ['request', 'responseUrl', 'returnUrl'];

const originOf = (url, what) => {
  try {
    return new URL(url).origin;
  } catch {
    throw new HolderError('BAD_REQUEST', `The ${what} is not a URL.`);
  }
};

// Checks what a verifier served at requestUrl. `now` in Unix seconds.
export function acceptServedRequest(requestUrl, served, now = Date.now() / 1000) {
  const origin = originOf(requestUrl, 'request address');
  if (typeof served !== 'object' || served === null || typeof served.request !== 'object' || served.request === null) {
    throw new HolderError('BAD_REQUEST', 'The website sent something that is not a zkID request.');
  }
  const extra = [
    ...Object.keys(served).filter((k) => !SERVED_FIELDS.includes(k)),
    ...Object.keys(served.request).filter((k) => !REQUEST_FIELDS.includes(k)),
  ];
  if (extra.length) {
    throw new HolderError('UNSUPPORTED_REQUEST', `The website asks for more than this app proves (${extra.join(', ')}). It only proves "19 or older".`);
  }
  let request;
  try {
    request = checkRequest(served.request);
  } catch (err) {
    throw new HolderError('BAD_REQUEST', `The request is malformed: ${err.message}`);
  }
  if (request.verifierId !== origin) {
    throw new HolderError('WRONG_ORIGIN', `The request names ${request.verifierId}, but came from ${origin}.`);
  }
  for (const [name, url] of [['proof address', served.responseUrl], ['return address', served.returnUrl]]) {
    if (originOf(url, name) !== origin) throw new HolderError('WRONG_ORIGIN', `The ${name} is not on ${origin}.`);
  }
  if (now > request.expiresAt) throw new HolderError('REQUEST_EXPIRED', 'The request has expired. Start again from the website.');
  return { request, responseUrl: served.responseUrl, returnUrl: served.returnUrl };
}

export async function fetchRequest(requestUrl) {
  let res;
  try {
    res = await fetch(requestUrl, { credentials: 'omit' });
  } catch {
    throw new HolderError('REQUEST_UNAVAILABLE', `Could not reach ${requestUrl}.`);
  }
  if (!res.ok) throw new HolderError('REQUEST_UNAVAILABLE', `The website answered HTTP ${res.status}.`);
  return acceptServedRequest(requestUrl, await res.json());
}

// The two public inputs a proof for this request must carry.
export async function publicInputsFor(request) {
  return { nullifierSeed: await nullifierSeedFor(request.verifierId), signalHash: await signalHashFor(request) };
}
