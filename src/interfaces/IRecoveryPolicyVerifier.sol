// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "./IERC7093.sol";

/// @notice Pluggable ERC-7093 recovery policy decision point.
interface IRecoveryPolicyVerifier {
    /// @notice Returns success and accumulated weight from stored configuration; `properties` is ignored.
    function verifyRecoveryPolicy(IERC7093.Permission[] calldata permissions, uint64[] calldata properties)
        external
        view
        returns (bool succ, uint64 weight);

    function getPolicyVerifierInfo() external pure returns (bytes memory);
}
