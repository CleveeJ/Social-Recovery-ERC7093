// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/* solhint-disable reason-string */

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IERC7093} from "./interfaces/IERC7093.sol";
import {ISmartAccount} from "./interfaces/ISmartAccount.sol";
import {IRecoveryPolicyVerifier} from "./interfaces/IRecoveryPolicyVerifier.sol";
import {IPermissionVerifier} from "./interfaces/IPermissionVerifier.sol";
import {SimpleThresholdPolicyVerifier} from "./verifiers/SimpleThresholdPolicyVerifier.sol";

/// @title RecoveryModule
/// @notice ERC-7093-aligned social recovery module (multi-tenant): one deployed module
///         serves many `SmartAccount`s, with all recovery state keyed by `account`.
/// @dev Responsibilities are limited to RECOVERY: verify guardian sigs, enforce the
///      threshold/time-lock policy, then call `SmartAccount.recoverOwner()` once matured.
///      It does NOT participate in normal ERC-4337 authorization. State per account:
///        - `accounts[account].configs`      → verifier + threshold tiers
///        - `accounts[account].pending`      → active recovery per config index
///        - `accounts[account].recoveryNonce` → per-account replay nonce
///      Guardian sig checking: empty `signer` ⇒ SignatureChecker (EOA/ERC-1271);
///      non-empty ⇒ the guardian's `IPermissionVerifier`. The EIP-712 digest binds
///      this module + `account`, preventing cross-account replay. Keep this contract
///      minimal/immutable (logic delegated to per-config verifiers) as it is a shared SPOF.
contract RecoveryModule is EIP712 {
    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    /// @dev A recovery config: the policy verifier (holds the guardian set) + threshold tiers.
    struct RecoveryConfig {
        address policyVerifier;
        IERC7093.ThresholdConfig[] thresholdConfigs;
    }

    /// @dev Pending recovery state, per (account, config index).
    struct PendingRecovery {
        bytes newOwner;
        uint256 nonce;
        uint48 executeAfter;
        bool active;
    }

    /// @dev All recovery state for a single account. Keyed by the account address in
    ///      the top-level `accounts` mapping.
    struct AccountRecovery {
        RecoveryConfig[] configs;
        mapping(uint256 => PendingRecovery) pending;
        uint256 recoveryNonce;
    }

    /// @dev EIP-712 request type. Binds domain + account + configIndex + newOwner + nonce,
    ///      so a guardian signature can't be replayed on another account/config/owner/nonce.
    struct RecoveryRequest {
        uint256 configIndex;
        address account;
        bytes newOwner;
        uint256 nonce;
    }

    /// @dev EIP-7093 `StartRecovery` type hash; includes `account` for a shared module.
    bytes32 private constant RECOVERY_REQUEST_TYPEHASH =
        keccak256("StartRecovery(uint256 configIndex,address account,bytes newOwners,uint256 nonce)");

    string private constant _DOMAIN_NAME = "ERC7093Recovery";
    string private constant _DOMAIN_VERSION = "1";

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    /// @notice Per-account recovery state. Keyed by the SmartAccount address.
    mapping(address => AccountRecovery) internal accounts;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event RecoveryStarted(bytes newOwners, uint256 nonce, uint48 expiryTime);
    event RecoveryExecuted(bytes newOwners, uint256 nonce);
    event RecoveryCanceled(uint256 nonce);
    event RecoveryConfigured(address indexed account, uint256 indexed configIndex, address indexed policyVerifier);

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor() EIP712(_DOMAIN_NAME, _DOMAIN_VERSION) {}

    // ---------------------------------------------------------------------
    // EIP-712 domain (EIP-7093 IRecoveryAccount surface)
    // ---------------------------------------------------------------------

    function DOMAIN_SEPARATOR_NAME() external pure returns (string memory) {
        return _DOMAIN_NAME;
    }

    function DOMAIN_SEPARATOR_VERSION() external pure returns (string memory) {
        return _DOMAIN_VERSION;
    }

    function domainSeparatorV4() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ---------------------------------------------------------------------
    // Configuration (owner-only, per account) — EIP-7093 updateGuardians
    // ---------------------------------------------------------------------

    /// @notice Replace ALL recovery configurations for `account` (owner-only, EIP's onlySelf).
    /// @dev Each `policyVerifier` must be a deployed IRecoveryPolicyVerifier holding the guardian set.
    function updateGuardians(address account, IERC7093.RecoveryConfigArg[] calldata args) external {
        require(account != address(0), "RecoveryModule: zero account");
        require(ISmartAccount(account).owner() == msg.sender, "RecoveryModule: not owner");
        require(args.length > 0, "RecoveryModule: empty configs");

        // Clear previous config (recursively frees nested).
        delete accounts[account];

        AccountRecovery storage ar = accounts[account];
        for (uint256 i = 0; i < args.length; i++) {
            IERC7093.RecoveryConfigArg calldata arg = args[i];
            require(arg.guardianInfos.length > 0, "RecoveryModule: empty guardians");
            require(arg.thresholdConfigs.length > 0, "RecoveryModule: empty threshold");
            require(arg.policyVerifier != address(0), "RecoveryModule: zero policyVerifier");

            RecoveryConfig storage cfg = ar.configs.push();
            cfg.policyVerifier = arg.policyVerifier;
            for (uint256 j = 0; j < arg.thresholdConfigs.length; j++) {
                cfg.thresholdConfigs.push(arg.thresholdConfigs[j]);
            }

            emit RecoveryConfigured(account, i, arg.policyVerifier);
        }
    }

    // ---------------------------------------------------------------------
    // EIP-712 recovery digest
    // ---------------------------------------------------------------------

    /// @notice EIP-712 digest a guardian signs to authorize a recovery for `account`.
    function getRecoveryDigest(address account, uint256 configIndex, bytes calldata newOwner)
        public
        view
        returns (bytes32)
    {
        return _digestFor(account, configIndex, newOwner, accounts[account].recoveryNonce);
    }

    /// @dev Digest for a specific nonce: startRecovery uses the current nonce; cancelRecoveryByGuardians the pending one.
    function _digestFor(address account, uint256 configIndex, bytes memory newOwner, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(RECOVERY_REQUEST_TYPEHASH, configIndex, account, keccak256(newOwner), nonce))
        );
    }

    // ---------------------------------------------------------------------
    // Recovery nonce (ERC-7093, per account, separate from ERC-4337)
    // ---------------------------------------------------------------------

    function getRecoveryNonce(address account) external view returns (uint256) {
        return accounts[account].recoveryNonce;
    }

    /// @notice Active/most-recent pending recovery for an account + config index.
    function getPendingRecovery(address account, uint256 configIndex) external view returns (PendingRecovery memory) {
        return accounts[account].pending[configIndex];
    }

    // ---------------------------------------------------------------------
    // Lifecycle: startRecovery
    // ---------------------------------------------------------------------

    /// @notice Start a social recovery for `account` (anyone may call; authorized by guardian sigs).
    /// @dev Flow: compute digest → verify guardian sigs → policy verifier returns weight →
    ///      pick time-lock tier → store pending recovery → increment recoveryNonce → emit.
    function startRecovery(
        address account,
        uint256 configIndex,
        bytes calldata newOwner,
        IERC7093.Permission[] calldata permissions
    ) external {
        require(account != address(0), "RecoveryModule: zero account");
        AccountRecovery storage ar = accounts[account];
        require(configIndex < ar.configs.length, "RecoveryModule: invalid configIndex");
        RecoveryConfig storage cfg = ar.configs[configIndex];

        address decoded = abi.decode(newOwner, (address));
        require(decoded != address(0), "RecoveryModule: zero newOwner");

        bytes32 digest = getRecoveryDigest(account, configIndex, newOwner);

        // Verify each guardian signature (before the policy check).
        _verifyGuardianSignatures(digest, permissions);

        // Policy check: membership + accumulated weight.
        (bool ok, uint64 weight) =
            IRecoveryPolicyVerifier(cfg.policyVerifier).verifyRecoveryPolicy(permissions, _zeroProps(permissions.length));
        require(ok, "RecoveryModule: verification failed");

        // Pick the time-lock tier (highest threshold <= weight).
        (bool matched, uint48 lockPeriod) = _selectTier(cfg.thresholdConfigs, weight);
        require(matched, "RecoveryModule: verification failed");

        uint48 executeAfter =
            lockPeriod > 0 ? uint48(block.timestamp) + uint48(lockPeriod) : uint48(block.timestamp);

        uint256 usedNonce = ar.recoveryNonce;
        ar.pending[configIndex] = PendingRecovery({newOwner: newOwner, nonce: usedNonce, executeAfter: executeAfter, active: true});

        // Advance the recovery nonce so these exact signatures cannot be replayed.
        ar.recoveryNonce += 1;

        emit RecoveryStarted(newOwner, usedNonce, executeAfter);
    }

    /// @dev Empty `signer` ⇒ SignatureChecker (EOA/ERC-1271); non-empty ⇒ guardian's IPermissionVerifier.
    function _verifyGuardianSignatures(bytes32 digest, IERC7093.Permission[] calldata permissions) internal {
        for (uint256 i = 0; i < permissions.length; i++) {
            IERC7093.Permission calldata p = permissions[i];
            if (p.guardian.signer.length == 0) {
                require(
                    SignatureChecker.isValidSignatureNow(p.guardian.guardianVerifier, digest, p.signature),
                    "RecoveryModule: bad guardian signature"
                );
            } else {
                require(
                    IPermissionVerifier(p.guardian.guardianVerifier).isValidPermission(digest, p.guardian.signer, p.signature),
                    "RecoveryModule: bad guardian signature"
                );
            }
        }
    }

    /// @dev Highest threshold `<= weight` wins (returns false,0 if none). Negative lockPeriod treated as 0.
    function _selectTier(IERC7093.ThresholdConfig[] storage tiers, uint64 weight)
        internal
        view
        returns (bool matched, uint48 lockPeriod)
    {
        uint64 bestThreshold = 0;
        bool found = false;
        for (uint256 i = 0; i < tiers.length; i++) {
            if (weight >= tiers[i].threshold) {
                if (!found || tiers[i].threshold > bestThreshold) {
                    bestThreshold = tiers[i].threshold;
                    lockPeriod = tiers[i].lockPeriod >= 0 ? uint48(uint48(tiers[i].lockPeriod)) : 0;
                    found = true;
                }
            }
        }
        matched = found;
    }

    function _zeroProps(uint256 len) internal pure returns (uint64[] memory) {
        return new uint64[](len);
    }

    // ---------------------------------------------------------------------
    // Lifecycle: executeRecovery
    // ---------------------------------------------------------------------

    /// @notice Execute a started recovery after its time-lock elapses (anyone may finalize).
    /// @dev Requires an active recovery and block.timestamp >= executeAfter; then rotates the owner.
    function executeRecovery(address account, uint256 configIndex) external {
        require(account != address(0), "RecoveryModule: zero account");
        AccountRecovery storage ar = accounts[account];
        PendingRecovery storage p = ar.pending[configIndex];
        require(p.active, "RecoveryModule: no active recovery");
        require(block.timestamp >= p.executeAfter, "RecoveryModule: time lock active");

        // Invalidate before the external call (checks-effects-interactions).
        p.active = false;
        emit RecoveryExecuted(p.newOwner, p.nonce);
        ISmartAccount(account).recoverOwner(p.newOwner);
    }

    // ---------------------------------------------------------------------
    // Lifecycle: cancelRecovery (owner-only, per account)
    // ---------------------------------------------------------------------

    /// @notice Cancel an active recovery (only the account owner may call).
    function cancelRecovery(address account, uint256 configIndex) external {
        require(account != address(0), "RecoveryModule: zero account");
        require(ISmartAccount(account).owner() == msg.sender, "RecoveryModule: not owner");
        PendingRecovery storage p = accounts[account].pending[configIndex];
        require(p.active, "RecoveryModule: no active recovery");

        uint256 nonce = p.nonce;
        p.active = false;
        emit RecoveryCanceled(nonce);
    }

    // ---------------------------------------------------------------------
    // Lifecycle: cancelRecoveryByGuardians (guardian-quorum cancellation)
    // ---------------------------------------------------------------------

    /// @notice Cancel an active recovery via a guardian quorum (meets the first/minimum threshold).
    /// @dev Signatures are bound to the pending recovery's nonce + account.
    function cancelRecoveryByGuardians(
        address account,
        uint256 configIndex,
        IERC7093.Permission[] calldata permissions
    ) external {
        require(account != address(0), "RecoveryModule: zero account");
        AccountRecovery storage ar = accounts[account];
        PendingRecovery storage p = ar.pending[configIndex];
        require(p.active, "RecoveryModule: no active recovery");
        RecoveryConfig storage cfg = ar.configs[configIndex];

        bytes32 digest = _digestFor(account, configIndex, p.newOwner, p.nonce);
        _verifyGuardianSignatures(digest, permissions);

        (bool ok, uint64 weight) =
            IRecoveryPolicyVerifier(cfg.policyVerifier).verifyRecoveryPolicy(permissions, _zeroProps(permissions.length));
        require(ok, "RecoveryModule: verification failed");
        require(weight >= cfg.thresholdConfigs[0].threshold, "RecoveryModule: quorum not met");

        uint256 nonce = p.nonce;
        p.active = false;
        emit RecoveryCanceled(nonce);
    }

    // ---------------------------------------------------------------------
    // Views (EIP-7093 IRecoveryAccount surface, per account)
    // ---------------------------------------------------------------------

    function getRecoveryStatus(address account, uint256 configIndex)
        external
        view
        returns (bool isRecovering, uint48 expiryTime)
    {
        PendingRecovery storage p = accounts[account].pending[configIndex];
        return (p.active, p.executeAfter);
    }

    function isGuardian(address account, uint256 configIndex, IERC7093.Identity calldata guardian)
        external
        view
        returns (bool)
    {
        IERC7093.GuardianInfo[] memory gs = _guardiansOf(account, configIndex);
        for (uint256 i = 0; i < gs.length; i++) {
            if (
                gs[i].guardian.guardianVerifier == guardian.guardianVerifier
                    && keccak256(gs[i].guardian.signer) == keccak256(guardian.signer)
            ) {
                return true;
            }
        }
        return false;
    }

    function getGuardians(address account, uint256 configIndex) external view returns (IERC7093.GuardianInfo[] memory) {
        return _guardiansOf(account, configIndex);
    }

    function getThresholdConfigs(address account, uint256 configIndex)
        external
        view
        returns (IERC7093.ThresholdConfig[] memory)
    {
        return accounts[account].configs[configIndex].thresholdConfigs;
    }

    function getPolicyVerifier(address account, uint256 configIndex) external view returns (address) {
        return accounts[account].configs[configIndex].policyVerifier;
    }

    /// @notice Reconstruct the full recovery configuration(s) for an account.
    function getRecoveryConfigs(address account) external view returns (IERC7093.RecoveryConfigArg[] memory) {
        uint256 n = accounts[account].configs.length;
        IERC7093.RecoveryConfigArg[] memory out = new IERC7093.RecoveryConfigArg[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = IERC7093.RecoveryConfigArg(
                accounts[account].configs[i].policyVerifier,
                _guardiansOf(account, i),
                accounts[account].configs[i].thresholdConfigs
            );
        }
        return out;
    }

    /// @dev Read the authoritative guardian set from the config's policy verifier.
    function _guardiansOf(address account, uint256 configIndex) internal view returns (IERC7093.GuardianInfo[] memory) {
        require(configIndex < accounts[account].configs.length, "RecoveryModule: invalid configIndex");
        return SimpleThresholdPolicyVerifier(accounts[account].configs[configIndex].policyVerifier).getGuardians();
    }
}
