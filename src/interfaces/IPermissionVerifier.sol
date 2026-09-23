// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice ERC-7093 permission (signature/proof) verification for non-account guardians.
interface IPermissionVerifier {
    function isValidSigners(bytes[] calldata signers) external returns (bool);

    function isValidPermission(bytes32 hash, bytes calldata signer, bytes calldata signature) external returns (bool);

    function isValidPermissions(bytes32 hash, bytes[] calldata signers, bytes[] calldata signatures)
        external
        returns (bool);

    function getGuardianVerifierInfo() external view returns (bytes memory);
}
