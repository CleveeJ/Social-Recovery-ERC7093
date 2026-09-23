// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/* solhint-disable reason-string */

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_EXECUTOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IERC7093} from "./interfaces/IERC7093.sol";
import {ISmartAccount} from "./interfaces/ISmartAccount.sol";
import {IRecoveryPolicyVerifier} from "./interfaces/IRecoveryPolicyVerifier.sol";
import {IPermissionVerifier} from "./interfaces/IPermissionVerifier.sol";

/// @title RecoveryModule
/// @notice ERC-7093 social recovery as an ERC-7579 executor module, keyed by account.
contract RecoveryModule is EIP712, IERC7579Module {
    struct RecoveryConfig {
        address policyVerifier;
        IERC7093.GuardianInfo[] guardianInfos;
        IERC7093.ThresholdConfig[] thresholdConfigs;
    }

    struct PendingRecovery {
        bytes newOwner;
        uint256 nonce;
        uint48 executeAfter;
        bool active;
    }

    struct AccountRecovery {
        RecoveryConfig[] configs;
        mapping(uint256 => PendingRecovery) pending;
        uint256 recoveryNonce;
    }

    struct RecoveryRequest {
        uint256 configIndex;
        address account;
        bytes newOwner;
        uint256 nonce;
    }

    bytes32 private constant RECOVERY_REQUEST_TYPEHASH =
        keccak256("StartRecovery(uint256 configIndex,address account,bytes newOwners,uint256 nonce)");

    string private constant _DOMAIN_NAME = "ERC7093Recovery";
    string private constant _DOMAIN_VERSION = "1";

    mapping(address => AccountRecovery) internal accounts;

    /// @dev Install-gated flag. Start/execute/guardian-cancel require it.
    mapping(address => bool) public installed;

    event RecoveryStarted(bytes newOwners, uint256 nonce, uint48 expiryTime);
    event RecoveryExecuted(bytes newOwners, uint256 nonce);
    event RecoveryCanceled(uint256 nonce);
    event RecoveryConfigured(address indexed account, uint256 indexed configIndex, address indexed policyVerifier);

    constructor() EIP712(_DOMAIN_NAME, _DOMAIN_VERSION) {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    /// @notice `data` is `abi.encode(RecoveryConfigArg[])`.
    function onInstall(bytes calldata data) external {
        require(data.length > 0, "RecoveryModule: empty init");
        IERC7093.RecoveryConfigArg[] memory args = abi.decode(data, (IERC7093.RecoveryConfigArg[]));
        _configure(msg.sender, args);
        installed[msg.sender] = true;
        accounts[msg.sender].recoveryNonce += 1;
    }

    function onUninstall(bytes calldata) external {
        installed[msg.sender] = false;
    }

    /// @notice Replace all recovery configurations for `account`. Owner only.
    function updateGuardians(address account, IERC7093.RecoveryConfigArg[] calldata args) external {
        require(account != address(0), "RecoveryModule: zero account");
        require(ISmartAccount(account).owner() == msg.sender, "RecoveryModule: not owner");
        _configure(account, args);
        installed[account] = true;
    }

    function _configure(address account, IERC7093.RecoveryConfigArg[] memory args) internal {
        require(args.length > 0, "RecoveryModule: empty configs");
        delete accounts[account];

        AccountRecovery storage ar = accounts[account];
        for (uint256 i = 0; i < args.length; i++) {
            IERC7093.RecoveryConfigArg memory arg = args[i];
            require(arg.guardianInfos.length > 0, "RecoveryModule: empty guardians");
            require(arg.thresholdConfigs.length > 0, "RecoveryModule: empty threshold");
            require(arg.policyVerifier != address(0), "RecoveryModule: zero policyVerifier");

            RecoveryConfig storage cfg = ar.configs.push();
            cfg.policyVerifier = arg.policyVerifier;
            for (uint256 j = 0; j < arg.guardianInfos.length; j++) {
                cfg.guardianInfos.push(arg.guardianInfos[j]);
            }
            for (uint256 j = 0; j < arg.thresholdConfigs.length; j++) {
                cfg.thresholdConfigs.push(arg.thresholdConfigs[j]);
            }

            emit RecoveryConfigured(account, i, arg.policyVerifier);
        }
    }

    /// @notice EIP-712 digest guardians sign for `account`.
    function getRecoveryDigest(address account, uint256 configIndex, bytes calldata newOwner)
        public
        view
        returns (bytes32)
    {
        return _digestFor(account, configIndex, newOwner, accounts[account].recoveryNonce);
    }

    function _digestFor(address account, uint256 configIndex, bytes memory newOwner, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(RECOVERY_REQUEST_TYPEHASH, configIndex, account, keccak256(newOwner), nonce))
        );
    }

    function getRecoveryNonce(address account) external view returns (uint256) {
        return accounts[account].recoveryNonce;
    }

    function getPendingRecovery(address account, uint256 configIndex) external view returns (PendingRecovery memory) {
        return accounts[account].pending[configIndex];
    }

    /// @notice Start a recovery for `account`. Anyone may call; guardian signatures authorize.
    /// Only one active recovery per account across all configs.
    function startRecovery(
        address account,
        uint256 configIndex,
        bytes calldata newOwner,
        IERC7093.Permission[] calldata permissions
    ) external {
        require(account != address(0), "RecoveryModule: zero account");
        require(installed[account], "RecoveryModule: not installed");
        AccountRecovery storage ar = accounts[account];
        require(configIndex < ar.configs.length, "RecoveryModule: invalid configIndex");
        RecoveryConfig storage cfg = ar.configs[configIndex];

        address decoded = abi.decode(newOwner, (address));
        require(decoded != address(0), "RecoveryModule: zero newOwner");

        bytes32 digest = getRecoveryDigest(account, configIndex, newOwner);

        _verifyGuardianSignatures(digest, permissions);

        (bool ok, uint48 lockPeriod) = IRecoveryPolicyVerifier(cfg.policyVerifier)
            .verifyRecoveryPolicy(
                permissions, IERC7093.PolicyConfig({guardians: cfg.guardianInfos, thresholds: cfg.thresholdConfigs})
            );
        require(ok, "RecoveryModule: verification failed");

        for (uint256 i = 0; i < ar.configs.length; i++) {
            require(!ar.pending[i].active, "RecoveryModule: recovery already active");
        }

        uint48 executeAfter = lockPeriod > 0 ? uint48(block.timestamp) + lockPeriod : uint48(block.timestamp);

        uint256 usedNonce = ar.recoveryNonce;
        ar.pending[configIndex] =
            PendingRecovery({newOwner: newOwner, nonce: usedNonce, executeAfter: executeAfter, active: true});
        ar.recoveryNonce += 1;

        emit RecoveryStarted(newOwner, usedNonce, executeAfter);
    }

    /// @dev Empty `signer` means an EOA / ERC-1271 account checked directly.
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
                    IPermissionVerifier(p.guardian.guardianVerifier)
                        .isValidPermission(digest, p.guardian.signer, p.signature),
                    "RecoveryModule: bad guardian signature"
                );
            }
        }
    }

    /// @notice Execute a matured recovery. Anyone may finalize after the timelock.
    function executeRecovery(address account, uint256 configIndex) external {
        require(account != address(0), "RecoveryModule: zero account");
        require(installed[account], "RecoveryModule: not installed");
        AccountRecovery storage ar = accounts[account];
        PendingRecovery storage p = ar.pending[configIndex];
        require(p.active, "RecoveryModule: no active recovery");
        require(block.timestamp >= p.executeAfter, "RecoveryModule: time lock active");

        p.active = false;
        emit RecoveryExecuted(p.newOwner, p.nonce);

        bytes memory execution =
            abi.encodePacked(account, uint256(0), abi.encodeCall(ISmartAccount.recoverOwner, (p.newOwner)));
        IERC7579Execution(account).executeFromExecutor(bytes32(0), execution);
    }

    /// @notice Cancel an active recovery. Owner only.
    function cancelRecovery(address account, uint256 configIndex) external {
        require(account != address(0), "RecoveryModule: zero account");
        require(ISmartAccount(account).owner() == msg.sender, "RecoveryModule: not owner");
        PendingRecovery storage p = accounts[account].pending[configIndex];
        require(p.active, "RecoveryModule: no active recovery");

        uint256 nonce = p.nonce;
        p.active = false;
        emit RecoveryCanceled(nonce);
    }

    /// @notice Cancel an active recovery via guardian quorum (minimum threshold).
    function cancelRecoveryByGuardians(address account, uint256 configIndex, IERC7093.Permission[] calldata permissions)
        external
    {
        require(account != address(0), "RecoveryModule: zero account");
        require(installed[account], "RecoveryModule: not installed");
        AccountRecovery storage ar = accounts[account];
        PendingRecovery storage p = ar.pending[configIndex];
        require(p.active, "RecoveryModule: no active recovery");
        RecoveryConfig storage cfg = ar.configs[configIndex];

        bytes32 digest = _digestFor(account, configIndex, p.newOwner, p.nonce);
        _verifyGuardianSignatures(digest, permissions);

        (bool ok,) = IRecoveryPolicyVerifier(cfg.policyVerifier)
            .verifyRecoveryPolicy(
                permissions, IERC7093.PolicyConfig({guardians: cfg.guardianInfos, thresholds: cfg.thresholdConfigs})
            );
        require(ok, "RecoveryModule: verification failed");

        uint256 nonce = p.nonce;
        p.active = false;
        emit RecoveryCanceled(nonce);
    }

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
        IERC7093.GuardianInfo[] storage gs = accounts[account].configs[configIndex].guardianInfos;
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
        return accounts[account].configs[configIndex].guardianInfos;
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

    function getRecoveryConfigs(address account) external view returns (IERC7093.RecoveryConfigArg[] memory) {
        uint256 n = accounts[account].configs.length;
        IERC7093.RecoveryConfigArg[] memory out = new IERC7093.RecoveryConfigArg[](n);
        for (uint256 i = 0; i < n; i++) {
            RecoveryConfig storage cfg = accounts[account].configs[i];
            out[i] = IERC7093.RecoveryConfigArg(cfg.policyVerifier, cfg.guardianInfos, cfg.thresholdConfigs);
        }
        return out;
    }
}
