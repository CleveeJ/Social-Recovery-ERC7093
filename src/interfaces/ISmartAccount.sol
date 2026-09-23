// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface ISmartAccount {
    /// @notice Rotate the owner. `newOwner` is an ABI-encoded address.
    function recoverOwner(bytes calldata newOwner) external;

    function owner() external view returns (address);
}
