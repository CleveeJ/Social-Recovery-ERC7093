// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC7579Validator, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ISmartAccount} from "../interfaces/ISmartAccount.sol";

/// @title SimpleECDSAValidator
/// @notice Stateless ERC-7579 validator reading the live `owner` from the calling account.
contract SimpleECDSAValidator is IERC7579Validator {
    bytes4 internal constant _ERC1271_MAGIC = 0x1626ba7e;

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @notice Returns 0 if `userOp.signature` is the owner's eth-signed `userOpHash`, else 1.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        address owner = ISmartAccount(msg.sender).owner();
        (address recovered, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(userOpHash), userOp.signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return ERC4337Utils.SIG_VALIDATION_SUCCESS;
        }
        return ERC4337Utils.SIG_VALIDATION_FAILED;
    }

    /// @notice ERC-1271 magic value iff `signature` is the owner's eth-signed `hash`.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        address owner = ISmartAccount(msg.sender).owner();
        (address recovered, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(hash), signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return _ERC1271_MAGIC;
        }
        return bytes4(0xffffffff);
    }
}
