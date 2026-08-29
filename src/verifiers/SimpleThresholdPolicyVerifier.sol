// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "../interfaces/IERC7093.sol";
import {IRecoveryPolicyVerifier} from "../interfaces/IRecoveryPolicyVerifier.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Concrete ERC-7093 RecoveryPolicyVerifier: weighted threshold over a guardian set.
/// @dev Flow: RecoveryModule verifies sigs first → this checks each guardian is a unique
///      configured member → sums `GuardianInfo.property` → returns (succ, totalWeight).
///      The guardian set lives in this contract instance (one deployed per recovery config,
///      seeded by the owner and registered via `updateGuardians`); the module keeps the
///      threshold tiers. Security: weight comes from OWNER-CONFIGURED `guardian.property`,
///      NEVER caller-supplied `properties` (else a quorum could inflate weight to shorten the lock).
contract SimpleThresholdPolicyVerifier is IRecoveryPolicyVerifier {
    IERC7093.GuardianInfo[] private _guardians;

    constructor(IERC7093.GuardianInfo[] memory guardians) {
        require(guardians.length > 0, "SimpleThresholdPolicyVerifier: empty guardians");
        for (uint256 i = 0; i < guardians.length; i++) {
            _guardians.push(guardians[i]);
        }
    }

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

            // Find the guardian in the configured set; reject if missing or already used.
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
                return (false, 0); // not a configured guardian, or duplicate
            }

            totalWeight += _guardians[SafeCast.toUint256(matched)].property;
        }

        return (true, totalWeight);
    }

    function getPolicyVerifierInfo() external pure returns (bytes memory) {
        return "SimpleThresholdPolicyVerifier:weighted-threshold";
    }

    /// @dev Returns the authoritative guardian set (used by the module to build views).
    function getGuardians() external view returns (IERC7093.GuardianInfo[] memory) {
        return _guardians;
    }
}
