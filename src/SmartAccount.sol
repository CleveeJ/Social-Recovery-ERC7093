// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/* solhint-disable reason-string */

import "@account-abstraction/contracts/core/Helpers.sol";
import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ISmartAccount} from "./interfaces/ISmartAccount.sol";

/// @title SmartAccount
/// @notice Minimal ERC-4337 smart-contract wallet with an ERC-7093 recovery seam.
///         The owner authorizes UserOps; a single authorized RecoveryModule may rotate the owner.
contract SmartAccount is IAccount, ISmartAccount {
    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    /// @notice The single signer/authorizer; the RecoveryModule may rotate it after recovery.
    address public owner;

    /// @notice The trusted ERC-4337 EntryPoint singleton (immutable, so it can't be swapped).
    IEntryPoint public immutable entryPoint;

    /// @notice Sole address permitted to rotate owner via recoverOwner(); set by setRecoveryModule().
    address public recoveryModule;

    event OwnerChanged(address indexed newOwner);
    event RecoveryModuleSet(address indexed recoveryModule);

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor(IEntryPoint anEntryPoint, address initialOwner) {
        require(initialOwner != address(0), "SmartAccount: zero owner");
        require(address(anEntryPoint) != address(0), "SmartAccount: zero entryPoint");
        entryPoint = anEntryPoint;
        owner = initialOwner;
    }

    receive() external payable {}

    // ---------------------------------------------------------------------
    // Authorization abstraction (extension point)
    // ---------------------------------------------------------------------

    /// @dev Authorization boundary. Only `owner` authorized for now; centralized so future
    ///      modules/guardians can extend it without editing execute()/validateUserOp().
    function _isAuthorizedSigner(address signer) internal view virtual returns (bool) {
        return signer == owner;
    }

    /// @dev Allows calls from the trusted EntryPoint or an authorized signer.
    function _requireFromEntryPointOrAuthorized() internal view {
        require(msg.sender == address(entryPoint) || _isAuthorizedSigner(msg.sender), "SmartAccount: not authorized");
    }

    /// @notice Rotates the owner key.
    /// @dev Extension point for the RecoveryModule. The ERC-7093 recovery nonce is separate
    ///      from the ERC-4337 UserOp nonce and must never be mixed.
    function changeOwner(address newOwner) external {
        _requireFromEntryPointOrAuthorized();
        require(newOwner != address(0), "SmartAccount: zero owner");
        owner = newOwner;
        emit OwnerChanged(newOwner);
    }

    /// @notice Authorizes (or, with address(0), de-authorizes) the RecoveryModule that may rotate owner.
    /// @dev Only the owner may call this; recoverOwner() enforces msg.sender == recoveryModule.
    function setRecoveryModule(address recoveryModule_) external {
        require(msg.sender == owner, "SmartAccount: not owner");
        recoveryModule = recoveryModule_;
        emit RecoveryModuleSet(recoveryModule_);
    }

    /// @notice Recovers (rotates) owner after a validated ERC-7093 recovery.
    /// @dev Sole RecoveryModule owner-rotation path; strictly gated to recoveryModule.
    ///      newOwner is abi.encode(address) for ERC-7093 bytes-owner compatibility.
    function recoverOwner(bytes calldata newOwner) external {
        require(msg.sender == recoveryModule, "SmartAccount: not recovery module");
        address recovered = abi.decode(newOwner, (address));
        require(recovered != address(0), "SmartAccount: zero owner");
        owner = recovered;
        emit OwnerChanged(recovered);
    }

    // ---------------------------------------------------------------------
    // ERC-4337: validateUserOp
    // ---------------------------------------------------------------------

    /// @notice Validates a UserOperation's signature and pays the EntryPoint prefund.
    /// @dev Callable only by the trusted EntryPoint. Replay protection is the EntryPoint's
    ///      UserOp nonce (separate from the ERC-7093 recovery nonce). The signature is an
    ///      ECDSA sig by `owner` over userOpHash, checked modularly in _validateSignature.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        returns (uint256 validationData)
    {
        // EntryPoint authorization: only the trusted EntryPoint may call this.
        require(msg.sender == address(entryPoint), "SmartAccount: not from EntryPoint");

        validationData = _validateSignature(userOp, userOpHash);

        // Prefund the EntryPoint; failure to pay is the EntryPoint's concern.
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);

        // tryRecover reports malformed sigs as SIG_VALIDATION_FAILED instead of reverting.
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethSignedHash, userOp.signature);

        if (err != ECDSA.RecoverError.NoError || recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    // ---------------------------------------------------------------------
    // Transaction execution
    // ---------------------------------------------------------------------

    /// @notice Executes a transaction from this account.
    /// @dev Callable via EntryPoint (valid UserOp) or directly by the owner. Reverts bubbling the target's reason.
    function execute(address target, uint256 value, bytes calldata data) external {
        _requireFromEntryPointOrAuthorized();
        _call(target, value, data);
    }

    /// @dev Low-level call that bubbles up the target's revert reason.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
