// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Minimal ERC-1271 interface used for smart-contract Guardian signature
///         validation. A contract guardian returns the magic value
///         0x1626ba7e when it considers `signature` valid for `hash`.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}
