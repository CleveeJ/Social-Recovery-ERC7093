// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "./IERC7093.sol";

/// @notice Pluggable ERC-7093 recovery policy decision point, evaluated over supplied config.
interface IRecoveryPolicyVerifier {
    /// @notice Pure policy evaluation over the supplied config.
    function verifyRecoveryPolicy(IERC7093.Permission[] calldata permissions, IERC7093.PolicyConfig calldata config)
        external
        pure
        returns (bool ok, uint48 lockPeriod);

    function getPolicyVerifierInfo() external pure returns (bytes memory);
}
