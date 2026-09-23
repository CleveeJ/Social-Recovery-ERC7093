// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "../interfaces/IERC7093.sol";
import {IRecoveryPolicyVerifier} from "../interfaces/IRecoveryPolicyVerifier.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Stateless weighted-threshold policy: highest satisfied threshold wins.
contract SimpleThresholdPolicyVerifier is IRecoveryPolicyVerifier {
    /// @notice Returns success and the applicable lock period for the supplied config.
    function verifyRecoveryPolicy(IERC7093.Permission[] calldata permissions, IERC7093.PolicyConfig calldata config)
        external
        pure
        returns (bool ok, uint48 lockPeriod)
    {
        uint256 n = config.guardians.length;
        if (n == 0 || config.thresholds.length == 0) {
            return (false, 0);
        }
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
                    !used[j] && config.guardians[j].guardian.guardianVerifier == p.guardian.guardianVerifier
                        && keccak256(config.guardians[j].guardian.signer) == keccak256(p.guardian.signer)
                ) {
                    matched = SafeCast.toInt256(j);
                    used[j] = true;
                    break;
                }
            }
            if (matched < 0) {
                return (false, 0);
            }

            totalWeight += config.guardians[SafeCast.toUint256(matched)].property;
        }

        uint64 bestThreshold = 0;
        bool found = false;
        for (uint256 i = 0; i < config.thresholds.length; i++) {
            if (totalWeight >= config.thresholds[i].threshold) {
                if (!found || config.thresholds[i].threshold > bestThreshold) {
                    bestThreshold = config.thresholds[i].threshold;
                    lockPeriod =
                        config.thresholds[i].lockPeriod >= 0 ? uint48(uint48(config.thresholds[i].lockPeriod)) : 0;
                    found = true;
                }
            }
        }
        if (!found) {
            return (false, 0);
        }
        return (true, lockPeriod);
    }

    function getPolicyVerifierInfo() external pure returns (bytes memory) {
        return "SimpleThresholdPolicyVerifier:weighted-threshold";
    }
}
