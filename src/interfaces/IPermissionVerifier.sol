// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "./IERC7093.sol";

/// @notice ERC-7093 PermissionVerifier abstraction (EIP-conformant shape).
/// @dev Verifies a guardian's signature/proof. Per EIP-7093: empty `signer` ⇒ the
///      guardian is an EOA/SCA verified directly (ECDSA/ERC-1271), NOT via this interface;
///      non-empty `signer` (DKIM/ZKP/WebAuthn/NFT-SBT) ⇒ call
///      `IPermissionVerifier(guardianVerifier).isValidPermission(...)`. This interface
///      exists for full conformance and future non-account guardians.
interface IPermissionVerifier {
    /// @dev Check if the supplied signer key formats are correct.
    function isValidSigners(bytes[] calldata signers) external returns (bool);

    /// @dev Validate a single guardian's permission (signature/proof).
    /// @param hash      The EIP-712 recovery digest that was signed.
    /// @param signer    The guardian's sub-identity (empty for EOA/SCA).
    /// @param signature The guardian's signature/proof over `hash`.
    function isValidPermission(bytes32 hash, bytes calldata signer, bytes calldata signature) external returns (bool);

    /// @dev Validate a batch of guardian permissions.
    function isValidPermissions(bytes32 hash, bytes[] calldata signers, bytes[] calldata signatures)
        external
        returns (bool);

    /// @dev Returns supported signer/format/hash info.
    function getGuardianVerifierInfo() external view returns (bytes memory);
}
