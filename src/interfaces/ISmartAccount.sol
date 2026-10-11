// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC5313} from "@openzeppelin/contracts/interfaces/IERC5313.sol";

/// @notice Project account surface: ERC-5313 ownership plus the recovery seam.
/// `owner()` is inherited from `IERC5313`.
interface ISmartAccount is IERC5313 {
    /// @notice Rotate the owner. `newOwner` is an ABI-encoded address.
    function recoverOwner(bytes calldata newOwner) external;
}
