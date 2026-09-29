// ZkIdPolicy on a local chain, with the real verifiers and honest proofs of the
// mock issuer's sample credential (test/fixtures). The chain starts on
// 2026-09-27 (hardhat.config.js); the age proof's cutoff is 20080928.
const { expect } = require('chai');
const { ethers } = require('hardhat');
const { time } = require('@nomicfoundation/hardhat-network-helpers');

const ISSUER = require('../../../mock-issuer/circuit_inputs.json').modulus_limbs;
const fixture = (name) => require(`./fixtures/${name}.json`);
const Result = { Accepted: 0n, UntrustedIssuer: 1n, CutoffTooLate: 2n, NothingClaimed: 3n, InvalidProof: 4n };

// snarkjs -> Solidity calldata. pi_b's inner pairs are reversed for the verifier.
function calldata({ proof, publicSignals }) {
  return [
    [proof.pi_a[0], proof.pi_a[1]],
    [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    [proof.pi_c[0], proof.pi_c[1]],
    publicSignals,
  ];
}

// The backend's computeThresholdDate.
function cutoffFor(date) {
  return date.getUTCFullYear() * 10000 + (date.getUTCMonth() + 1) * 100 + date.getUTCDate() - 180000;
}

describe('ZkIdPolicy', () => {
  let policy;
  let owner;
  let other;

  before(async () => {
    [owner, other] = await ethers.getSigners();
    const age = await (await ethers.getContractFactory('CredentialAgeVerifier')).deploy();
    const match = await (await ethers.getContractFactory('CredentialMatchVerifier')).deploy();
    policy = await (await ethers.getContractFactory('ZkIdPolicy')).deploy(
      await age.getAddress(),
      await match.getAddress(),
      ISSUER
    );
  });

  it('computes the 18-year cutoff like the backend, leap days included', async () => {
    const days = [];
    for (let d = Date.UTC(2027, 0, 1); d <= Date.UTC(2028, 11, 31); d += 86400000) days.push(new Date(d));
    for (const s of ['1970-01-01', '2000-02-29', '2100-02-28', '2100-03-01', '2400-02-29', '2026-12-31']) {
      days.push(new Date(`${s}T23:59:59Z`));
    }
    for (const day of days) {
      expect(await policy.cutoffDate(Math.floor(day.getTime() / 1000))).to.equal(BigInt(cutoffFor(day)), day.toISOString());
    }
  });

  it("rejects a valid age proof whose cutoff is later than today's", async () => {
    expect(await policy.checkAge(...calldata(fixture('age')))).to.equal(Result.CutoffTooLate);
  });

  it('accepts it from the day that cutoff is reached, and later', async () => {
    await time.increaseTo(Date.UTC(2026, 8, 28) / 1000);
    expect(await policy.checkAge(...calldata(fixture('age')))).to.equal(Result.Accepted);
    await time.increaseTo(Date.UTC(2031, 0, 1) / 1000);
    expect(await policy.checkAge(...calldata(fixture('age')))).to.equal(Result.Accepted);
  });

  it('accepts name and gender proofs', async () => {
    expect(await policy.checkMatch(...calldata(fixture('match-name')))).to.equal(Result.Accepted);
    expect(await policy.checkMatch(...calldata(fixture('match-gender')))).to.equal(Result.Accepted);
  });

  it('rejects a valid proof that claims nothing', async () => {
    expect(await policy.checkMatch(...calldata(fixture('match-none')))).to.equal(Result.NothingClaimed);
  });

  it('rejects a corrupted proof', async () => {
    const [pA, pB, pC, signals] = calldata(fixture('age'));
    expect(await policy.checkAge(pA, pB, [pC[0], (BigInt(pC[1]) ^ 1n).toString()], signals)).to.equal(Result.InvalidProof);
    const [mA, mB, mC, mSignals] = calldata(fixture('match-name'));
    const otherName = [...mSignals];
    otherName[17] = '1';
    expect(await policy.checkMatch(mA, mB, mC, otherName)).to.equal(Result.InvalidProof);
  });

  it('rejects valid proofs once their issuer is no longer trusted', async () => {
    await policy.setIssuer(ISSUER, false);
    expect(await policy.checkAge(...calldata(fixture('age')))).to.equal(Result.UntrustedIssuer);
    expect(await policy.checkMatch(...calldata(fixture('match-name')))).to.equal(Result.UntrustedIssuer);
    await policy.setIssuer(ISSUER, true);
    expect(await policy.checkAge(...calldata(fixture('age')))).to.equal(Result.Accepted);
  });

  it('lets only the owner change trusted issuers or ownership', async () => {
    await expect(policy.connect(other).setIssuer(ISSUER, false)).to.be.revertedWith('ZkIdPolicy: caller is not the owner');
    await expect(policy.connect(other).transferOwnership(other.address)).to.be.revertedWith('ZkIdPolicy: caller is not the owner');
    expect(await policy.trustedIssuers(await policy.issuerKeyHash(ISSUER))).to.equal(true);
    expect(await policy.owner()).to.equal(owner.address);
  });
});
