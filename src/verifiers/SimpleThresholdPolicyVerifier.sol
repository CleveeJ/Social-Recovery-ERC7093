// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "../interfaces/IERC7093.sol";
import {IRecoveryPolicyVerifier} from "../interfaces/IRecoveryPolicyVerifier.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Weighted-threshold recovery policy over a fixed guardian set.
contract SimpleThresholdPolicyVerifier is IRecoveryPolicyVerifier {
    IERC7093.GuardianInfo[] private _guardians;

    constructor(IERC7093.GuardianInfo[] memory guardians) {
        require(guardians.length > 0, "SimpleThresholdPolicyVerifier: empty guardians");
        for (uint256 i = 0; i < guardians.length; i++) {
            _guardians.push(guardians[i]);
        }
    }

    /// @notice Returns success and accumulated weight from stored configuration.
    function verifyRecoveryPolicy(
        IERC7093.Permission[] calldata permissions,
        uint64[] calldata /*properties*/
    )
        external
        view
        returns (bool succ, uint64 weight)
    {
        uint256 n = _guardians.length;
        if (permissions.length == 0 || permissions.length > n) {
            return (false, 0);
        }

        bool[] memory used = new bool[](n);
        uint64 totalWeight = 0;

        for (uint256 i = 0; i < permissions.length; i++) {
            IERC7093.Permission calldata p = permissions[i];

            int256 matched = -1;
            for (uint256 j = 0; j < n; j++) {
                if (
                    !used[j] && _guardians[j].guardian.guardianVerifier == p.guardian.guardianVerifier
                        && keccak256(_guardians[j].guardian.signer) == keccak256(p.guardian.signer)
                ) {
                    matched = SafeCast.toInt256(j);
                    used[j] = true;
                    break;
                }
            }
            if (matched < 0) {
                return (false, 0);
            }

            totalWeight += _guardians[SafeCast.toUint256(matched)].property;
        }

        return (true, totalWeight);
    }

    function getPolicyVerifierInfo() external pure returns (bytes memory) {
        return "SimpleThresholdPolicyVerifier:weighted-threshold";
    }

    function getGuardians() external view returns (IERC7093.GuardianInfo[] memory) {
        return _guardians;
    }
}
