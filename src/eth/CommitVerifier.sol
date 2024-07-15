// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./VerifierBase.sol";

contract CommitVerifier {
    uint constant f_r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    address public verifierBase;
    uint public maxPayloadBytes;

    constructor(address _verifierBase, uint _maxPayloadBytes) {
        verifierBase = _verifierBase;
        maxPayloadBytes = _maxPayloadBytes;
    }

    function verifyCommit(
        bytes memory instance,
        bytes memory proof
    ) public view {
        (
            uint signCommit,
            uint publicKeyHash,
            string[] memory payloadSubstrs,
            uint[] memory payloadSubstrStarts
        ) = abi.decode(instance, (uint, uint, string[], uint[]));
        uint rlc = 0;
        uint coeff = signCommit;
        bytes memory maskedChars;
        bytes memory substrIds;
        (maskedChars, substrIds) = getMaskedCharsAndIds(
            maxPayloadBytes,
            payloadSubstrs,
            payloadSubstrStarts
        );
        (rlc, coeff) = computeRLC(rlc, coeff, signCommit, maskedChars);
        (rlc, coeff) = computeRLC(rlc, coeff, signCommit, substrIds);

        VerifierBase verifier = VerifierBase(verifierBase);
        uint[] memory pubInputs = new uint[](3);
        pubInputs[0] = signCommit;
        pubInputs[1] = publicKeyHash;
        pubInputs[2] = rlc;
        require(verifier.verify(pubInputs, proof), "invalid proof");
    }

    function getMaskedCharsAndIds(
        uint maxBytes,
        string[] memory substrs,
        uint[] memory substrStarts
    ) private pure returns (bytes memory, bytes memory) {
        bytes memory expectedMaskedChars = new bytes(maxBytes);
        bytes memory expectedSubstrIds = new bytes(maxBytes);
        for (uint i = 0; i < substrs.length; i++) {
            uint startIdx = substrStarts[i];
            for (uint j = 0; j < bytes(substrs[i]).length; j++) {
                expectedMaskedChars[startIdx + j] = bytes(substrs[i])[j];
                expectedSubstrIds[startIdx + j] = bytes1(uint8(i + 1));
            }
        }
        return (expectedMaskedChars, expectedSubstrIds);
    }

    function computeRLC(
        uint rlc,
        uint coeff,
        uint rand,
        bytes memory inputs
    ) private pure returns (uint, uint) {
        uint muled = 0;
        uint input_byte = 0;
        for (uint i = 0; i < inputs.length; i++) {
            input_byte = uint(uint8(inputs[i]));
            assembly {
                muled := mulmod(input_byte, coeff, f_r)
                rlc := addmod(rlc, muled, f_r)
                coeff := mulmod(coeff, rand, f_r)
            }
        }
        return (rlc, coeff);
    }
}
