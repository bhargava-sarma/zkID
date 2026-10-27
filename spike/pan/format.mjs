// The DigiLocker PAN Verification Record as its XML signature covers it.
// DigiLocker signs (XMLDSig, enveloped) the exclusive-canonical form of the
// <Certificate> element without its <Signature>: SHA-256 of those bytes is the
// DigestValue, and SignedInfo, holding that digest, is signed with RSA-SHA1.
// Measured on one real record (the owner's, never committed); every value below
// is DigiLocker's format, not personal data.

// The canonical record, from its first byte to the start of the date of birth.
// It is fixed except for the PAN number: DigiLocker as issuer, Income Tax
// Department as the organization, status "A". A record that differs anywhere
// here cannot be proved (it fails closed).
export const DOC_HEAD = [
  '<Certificate issueDate="" issuedAt="DigiLocker" language="99" name="PAN Verification Record" number="',
  null, // the PAN number, 10 characters
  '" status="A" type="PANCR" validFromDate=""><IssuedBy><Organization code="" name="Income Tax Department" tin="" type="CG" uid="">' +
    '<Address country="IN" district="" house="" landmark="" line1="" line2="" locality="" pin="" state="" type="" vtc=""></Address>' +
    '</Organization></IssuedBy><IssuedTo><Person dob="',
];
export const PAN_LENGTH = 10;
export const PAN_OFFSET = DOC_HEAD[0].length;
export const DOB_OFFSET = PAN_OFFSET + PAN_LENGTH + DOC_HEAD[2].length;

// Canonical SignedInfo, exactly as DigiLocker writes it (its whitespace included).
export const SIGNED_INFO = [
  '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>\n' +
    '    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>\n' +
    '  <Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms>' +
    '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod><DigestValue>',
  null, // base64 of the SHA-256 digest, 44 characters
  '</DigestValue></Reference></SignedInfo>',
];
export const DIGEST_B64_LENGTH = 44;
export const signedInfoFor = (digestB64) => `${SIGNED_INFO[0]}${digestB64}${SIGNED_INFO[2]}`;

// The circuit hashes at most this many bytes of canonical record, SHA-256
// padding included: 56 blocks. One real record is 3,186 bytes (50 blocks); its
// QR image is most of it.
export const MAX_DOC_BYTES = 3584;
// The gender, uid and <PAN> attributes must start within this many bytes.
export const FIELD_WINDOW_BYTES = 1280;

export const GENDER_VALUES = { MALE: 'M', FEMALE: 'F', TRANSGENDER: 'T' };
