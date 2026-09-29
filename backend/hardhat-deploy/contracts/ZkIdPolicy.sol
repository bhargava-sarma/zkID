// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICredentialAgeVerifier {
    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[18] calldata _pubSignals) external view returns (bool);
}

interface ICredentialMatchVerifier {
    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[19] calldata _pubSignals) external view returns (bool);
}

/// @title ZkIdPolicy
/// @notice What a relying party checks on top of a zkID Groth16 proof. A valid
/// proof alone shows only that *some* RSA key signed a credential and, for age,
/// that its date of birth is on or before *some* cutoff. This contract also
/// requires the key to be on an owner-managed list of trusted issuers and, for
/// age, the cutoff to be no later than 18 years before today (UTC). Checks are
/// free view calls.
contract ZkIdPolicy {
    enum Result {
        Accepted,
        UntrustedIssuer,
        CutoffTooLate,
        NothingClaimed,
        InvalidProof
    }

    uint256 public constant MINIMUM_AGE_YEARS = 18;

    ICredentialAgeVerifier public immutable ageVerifier;
    ICredentialMatchVerifier public immutable matchVerifier;
    address public owner;

    /// keccak256 of an issuer's 17 modulus limbs (121 bits each, least significant first).
    mapping(bytes32 => bool) public trustedIssuers;

    event IssuerTrustChanged(bytes32 indexed keyHash, bool trusted);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "ZkIdPolicy: caller is not the owner");
        _;
    }

    constructor(address ageVerifier_, address matchVerifier_, uint256[17] memory issuerModulus) {
        ageVerifier = ICredentialAgeVerifier(ageVerifier_);
        matchVerifier = ICredentialMatchVerifier(matchVerifier_);
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        _setIssuer(issuerKeyHash(issuerModulus), true);
    }

    function setIssuer(uint256[17] calldata modulus, bool trusted) external onlyOwner {
        _setIssuer(issuerKeyHash(modulus), trusted);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZkIdPolicy: new owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function issuerKeyHash(uint256[17] memory modulus) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(modulus));
    }

    /// @notice Age proof (CredentialAgeProof). Public signals: 17 modulus limbs,
    /// then the cutoff date as YYYYMMDD. An earlier cutoff is only stricter.
    function checkAge(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[18] calldata pubSignals
    ) external view returns (Result) {
        if (!trustedIssuers[_issuerOf(pubSignals)]) return Result.UntrustedIssuer;
        if (pubSignals[17] > cutoffDate(block.timestamp)) return Result.CutoffTooLate;
        if (!ageVerifier.verifyProof(pA, pB, pC, pubSignals)) return Result.InvalidProof;
        return Result.Accepted;
    }

    /// @notice Name and gender proof (CredentialMatchProof). Public signals: 17
    /// modulus limbs, the claimed name hash, the claimed gender (1 M, 2 F, 3 O).
    /// A claim of 0 was not checked, so the caller must compare the claims it
    /// needs against pubSignals[17] and pubSignals[18].
    function checkMatch(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[19] calldata pubSignals
    ) external view returns (Result) {
        if (!trustedIssuers[_issuerOf(pubSignals)]) return Result.UntrustedIssuer;
        if (pubSignals[17] == 0 && pubSignals[18] == 0) return Result.NothingClaimed;
        if (!matchVerifier.verifyProof(pA, pB, pC, pubSignals)) return Result.InvalidProof;
        return Result.Accepted;
    }

    /// @notice Latest date of birth that is 18 or older on the day of `timestamp`,
    /// as YYYYMMDD (UTC). Same integer arithmetic as the backend: that day's
    /// YYYYMMDD minus 180000.
    function cutoffDate(uint256 timestamp) public pure returns (uint256) {
        (uint256 year, uint256 month, uint256 day) = _daysToDate(timestamp / 1 days);
        return (year - MINIMUM_AGE_YEARS) * 10000 + month * 100 + day;
    }

    function _setIssuer(bytes32 keyHash, bool trusted) private {
        trustedIssuers[keyHash] = trusted;
        emit IssuerTrustChanged(keyHash, trusted);
    }

    function _issuerOf(uint256[18] calldata pubSignals) private pure returns (bytes32) {
        uint256[17] memory modulus;
        for (uint256 i = 0; i < 17; i++) modulus[i] = pubSignals[i];
        return issuerKeyHash(modulus);
    }

    function _issuerOf(uint256[19] calldata pubSignals) private pure returns (bytes32) {
        uint256[17] memory modulus;
        for (uint256 i = 0; i < 17; i++) modulus[i] = pubSignals[i];
        return issuerKeyHash(modulus);
    }

    // Days since 1970-01-01 to a Gregorian date. From BokkyPooBah's DateTime
    // Library v1.01 (https://github.com/bokkypoobah/BokkyPooBahsDateTimeLibrary),
    // (c) BokkyPooBah / Bok Consulting Pty Ltd 2018-2019, MIT licence.
    int256 private constant OFFSET19700101 = 2440588;

    function _daysToDate(uint256 _days) private pure returns (uint256 year, uint256 month, uint256 day) {
        int256 __days = int256(_days);

        int256 L = __days + 68569 + OFFSET19700101;
        int256 N = (4 * L) / 146097;
        L = L - (146097 * N + 3) / 4;
        int256 _year = (4000 * (L + 1)) / 1461001;
        L = L - (1461 * _year) / 4 + 31;
        int256 _month = (80 * L) / 2447;
        int256 _day = L - (2447 * _month) / 80;
        L = _month / 11;
        _month = _month + 2 - 12 * L;
        _year = 100 * (N - 49) + _year + L;

        year = uint256(_year);
        month = uint256(_month);
        day = uint256(_day);
    }
}
