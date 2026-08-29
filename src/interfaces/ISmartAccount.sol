// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "./IERC7093.sol";

/// @notice Interface the RecoveryModule uses to rotate the SmartAccount owner.
/// @dev Strictly gated inside SmartAccount to the authorized RecoveryModule only,
///      so ownership can never be rotated by an arbitrary caller.
interface ISmartAccount {
    /// @notice Rotate the account owner as the result of a validated recovery.
    /// @param newOwner ABI-encoded `address` of the new owner.
    function recoverOwner(bytes calldata newOwner) external;

    /// @notice Current owner of the account (used by RecoveryModule for owner-only
    ///         actions such as cancelRecovery).
    function owner() external view returns (address);
}
