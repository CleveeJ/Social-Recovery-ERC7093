// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/* solhint-disable reason-string */

import "@account-abstraction/contracts/core/Helpers.sol";
import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SmartAccount
 * @notice Minimal ERC-4337 (account-abstraction) smart contract wallet.
 *
 * This is the Week 2 foundation of a thesis project whose final goal is a
 * social-recovery wallet based on the ERC-7093 draft. Only the ERC-4337
 * account foundation is implemented here; the recovery mechanism is intentionally
 * NOT implemented yet.
 *
 * Design goal: keep the account correct, simple and testable while leaving a
 * clear authorization boundary so that an ERC-7093 RecoveryModule can be added
 * later (Week 3) WITHOUT rewriting SmartAccount.
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │  SmartAccount                                                         │
 * │   ├── validateUserOp()      ← ERC-4337 entrypoint authorization       │
 * │   ├── execute()             ← owner / entrypoint authorized calls     │
 * │   └── (future) RecoveryModule ← will rotate `owner` via changeOwner() │
 * └──────────────────────────────────────────────────────────────────────┘
 */
contract SmartAccount is IAccount {
    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    /// @notice The single signer/authorizer of this account (Week 2 model).
    /// Note: the RecoveryModule (Week 3) will be able to rotate this value
    /// through changeOwner() after a successful ERC-7093 recovery, without
    /// changing the rest of the account logic.
    address public owner;

    /// @notice The canonical ERC-4337 EntryPoint singleton this account trusts.
    /// It is immutable to reduce gas and to guarantee the authorization target
    /// can never be silently swapped.
    IEntryPoint public immutable entryPoint;

    event OwnerChanged(address indexed newOwner);

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

    /**
     * @dev Authorization boundary.
     *
     * For Week 2 the ONLY authorized principal is `owner`. This check is
     * centralized here (instead of hard-coding `owner` in every function) so
     * that Week 3 can extend authorization — e.g. letting a RecoveryModule or
     * ERC-1271 guardian signatures authorize operations — by overriding
     * `_isAuthorizedSigner` (or adding a module allow-list), without editing
     * `execute()` or `validateUserOp()`.
     */
    function _isAuthorizedSigner(address signer) internal view virtual returns (bool) {
        return signer == owner;
    }

    /// @dev Allow calls that originate from the trusted EntryPoint OR from an
    ///      authorized signer. The EntryPoint path enforces the ERC-4337 nonce
    ///      and signature rules; the direct-owner path is a convenience for
    ///      off-chain owner control.
    function _requireFromEntryPointOrAuthorized() internal view {
        require(msg.sender == address(entryPoint) || _isAuthorizedSigner(msg.sender), "SmartAccount: not authorized");
    }

    /**
     * @notice Rotates the owner key.
     * @dev EXTENSION POINT: this is the precise seam the future ERC-7093
     *      RecoveryModule will use. In Week 3 the RecoveryModule, once a
     *      recovery is validated, will be granted the ability to call an
     *      equivalent privileged setter to replace `owner` with the recovered
     *      address. The ERC-7093 *recovery nonce* used by that module is a
     *      SEPARATE concept from the ERC-4337 transaction nonce handled by
     *      validateUserOp()/EntryPoint and must never be mixed with it.
     */
    function changeOwner(address newOwner) external {
        _requireFromEntryPointOrAuthorized();
        require(newOwner != address(0), "SmartAccount: zero owner");
        owner = newOwner;
        emit OwnerChanged(newOwner);
    }

    // ---------------------------------------------------------------------
    // ERC-4337: validateUserOp
    // ---------------------------------------------------------------------

    /**
     * @notice Validate a UserOperation's signature and pay the prefund.
     * @dev Part of the canonical IAccount interface required by the EntryPoint.
     *
     * Why this exists: the EntryPoint calls validateUserOp() during the
     * verification phase of handleOps(). If it returns successfully (or with
     * SIG_VALIDATION_SUCCESS) the operation proceeds to execution; otherwise the
     * operation is dropped. This is the contract's gatekeeper for ERC-4337.
     *
     * EntryPoint authorization: the function is only callable by the trusted
     * EntryPoint (enforced by the msg.sender check below). Any external account
     * calling it directly is rejected, so validation cannot be bypassed.
     *
     * Nonce / replay: replay protection relies entirely on the canonical
     * EntryPoint + UserOperation nonce mechanism. This account does NOT invent a
     * second transaction nonce. (The future ERC-7093 recovery flow uses its own
     * separate recovery nonce — do not confuse the two.)
     *
     * Week 2 authorization: the signature must be a valid ECDSA signature by
     * `owner` over the ERC-4337 userOpHash. The signature check is intentionally
     * modular (`_validateSignature`) so Week 3 can layer ERC-1271 / guardian-based
     * validation without rewriting this account.
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        returns (uint256 validationData)
    {
        // EntryPoint authorization: only the trusted EntryPoint may call this.
        require(msg.sender == address(entryPoint), "SmartAccount: not from EntryPoint");

        validationData = _validateSignature(userOp, userOpHash);

        // Pay the EntryPoint the funds missing from the account's deposit so the
        // operation can be executed. Failure to pay is the EntryPoint's concern,
        // so the result is intentionally ignored.
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

        // Use OZ's tryRecover so a malformed signature is reported as a
        // validation failure (SIG_VALIDATION_FAILED) rather than bubbling a
        // raw revert. Cryptographic recovery is delegated to OpenZeppelin's
        // audited library rather than reimplemented here.
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethSignedHash, userOp.signature);

        if (err != ECDSA.RecoverError.NoError || recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    // ---------------------------------------------------------------------
    // Transaction execution
    // ---------------------------------------------------------------------

    /**
     * @notice Execute a transaction from this account.
     * @dev Only callable through the EntryPoint (during a valid UserOperation)
     *      or directly by an authorized signer (`owner` for Week 2).
     *      Performs a low-level call to `target` with `value` and `data`, and
     *      reverts (bubbling up the target's revert reason) if the call fails.
     *      This proves the account can actually control assets and interact
     *      with arbitrary contracts.
     */
    function execute(address target, uint256 value, bytes calldata data) external {
        _requireFromEntryPointOrAuthorized();
        _call(target, value, data);
    }

    /// @dev Checks-effects-interactions: the authorization check (effect gate)
    ///      happens before the external call (interaction). Low-level call with
    ///      revert reason bubbling for clear failure semantics in tests.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
