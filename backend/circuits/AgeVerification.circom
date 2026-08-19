pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/*
 * AgeVerification — direct date comparison.
 *
 * Dates are encoded as a single integer: year*10000 + month*100 + day.
 * 1998-04-12 becomes 19980412. Because the fields are in descending order of
 * significance and each occupies a fixed decimal width, integer ordering on the
 * encoding is exactly chronological ordering on the date — so "is this person
 * old enough" reduces to one comparison.
 *
 * This replaces the previous days-since-epoch scheme, which computed
 * ageDays = todayDays - dobDays and compared against a hardcoded
 * thresholdDays = 6570 (18 * 365). That constant ignored leap days and was four
 * days too lenient: someone four days short of their 18th birthday verified as
 * an adult. Encoding dates directly removes the arithmetic entirely, so there is
 * no leap-year correction to get wrong.
 *
 * Public signals dropped from two (todayDays, thresholdDays) to one. todayDays
 * is no longer needed: the threshold date alone carries the claim. A relying
 * party checks thresholdDate is the date it expects — that it equals today minus
 * the required age — and the proof shows the subject was born on or before it.
 * Publishing an unconstrained todayDays would have been worse than useless,
 * since a prover picks it freely.
 */
template AgeVerification() {
    // Private — never revealed by the proof.
    signal input dobEncoded;

    // Public — the latest date of birth that still qualifies.
    signal input thresholdDate;

    // Born on or before the threshold => old enough.
    // 32 bits covers encodings up to 99991231, well under 2^32.
    component le = LessEqThan(32);
    le.in[0] <== dobEncoded;
    le.in[1] <== thresholdDate;

    // Assert rather than output: a witness exists only for someone who passes.
    le.out === 1;
}

component main {public [thresholdDate]} = AgeVerification();
