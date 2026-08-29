// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "../interfaces/IERC7093.sol";
import {IPermissionVerifier} from "../interfaces/IPermissionVerifier.sol";
import {IERC1271} from "../interfaces/IERC1271.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Concrete ERC-7093 PermissionVerifier for EOA and ERC-1271 SCA guardians.
/// @dev Implements `IPermissionVerifier`; non-account guardians (DKIM/ZKP/WebAuthn/
///      NFT-SBT) can be added later via a different verifier without touching the module.
///      For EOA/SCA the recovery flow uses OZ `SignatureChecker` (empty `signer`); the
///      `signer` arg is the ABI-encoded guardian address — code ⇒ ERC-1271, no code ⇒ ECDSA.
contract SimpleGuardianVerifier is IPermissionVerifier {
    /// @dev ERC-1271 success magic value.
    bytes4 internal constant _ERC1271_MAGIC = 0x1626ba7e;

    function isValidSigners(bytes[] calldata signers) external pure returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i].length != 32) return false;
            address acc = abi.decode(signers[i], (address));
            if (acc == address(0)) return false;
        }
        return true;
    }

    function isValidPermission(bytes32 hash, bytes calldata signer, bytes calldata signature)
        external
        view
        returns (bool)
    {
        if (signer.length != 32) return false;
        address acc = abi.decode(signer, (address));
        if (acc == address(0)) return false;

        if (acc.code.length == 0) {
            // EOA guardian: recover the signer via ECDSA.
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
            return err == ECDSA.RecoverError.NoError && recovered == acc;
        }

        // Smart-contract guardian: delegate to ERC-1271.
        try IERC1271(acc).isValidSignature(hash, signature) returns (bytes4 magic) {
            return magic == _ERC1271_MAGIC;
        } catch {
            return false;
        }
    }

    function isValidPermissions(bytes32 hash, bytes[] calldata signers, bytes[] calldata signatures)
        external
        view
        returns (bool)
    {
        if (signers.length != signatures.length) return false;
        for (uint256 i = 0; i < signers.length; i++) {
            if (!this.isValidPermission(hash, signers[i], signatures[i])) return false;
        }
        return true;
    }

    function getGuardianVerifierInfo() external pure returns (bytes memory) {
        return "SimpleGuardianVerifier:EOA+ECDSA,SCA+ERC1271";
    }
}
