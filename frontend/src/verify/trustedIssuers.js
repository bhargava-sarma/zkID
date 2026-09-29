// Issuers the verifier page accepts, by RSA-2048 modulus (big-endian hex). This
// list is the relying party's policy: a proof from any other key is rejected.
export const TRUSTED_ISSUERS = [
  {
    name: 'zkID demo issuer',
    // mock-issuer/mock_issuer_public.pem
    modulusHex:
      'e47464cd8c8a286aa4c048b8956ef563bdf6ac0990c2500b468f26f4edbf1f32a588de4aa781842957a610d5e7dc71bbb10c3cd7db067bd20faae3ca254d0e02c27349d33575b6052ec1b7bab1674181db8216fd663955a2be8b7e1aa5dcd23e03514f54e09f0aa9b34e1d8d144a5efc0325617be5a3d36043750d9dab10c30703aabe06ddef4847d0be71080fbdba4d1ff2990d45143de7da4fc46de74ec5fdc31bf7b9cdc803353872b0c1958268ac1714f019d4d4879b16e37582bd9c16982d64bd68ecbbf708a93a1805a7c66242e4b797449336ba36633dfa1955714d8b81a6f46b3607564932654b4b2d15749a9f9aa764da62f2d3a1857a6ebd99eb03',
  },
];
