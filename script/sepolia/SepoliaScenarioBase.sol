// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "../local/ArtifactLog.sol";

/// @notice Shared helpers for the Sepolia scenario suite (ping-pong happy path +
/// stateless and stateful attacks). Every scenario:
///   1. opens its own artifact file under `script/sepolia/logs/`,
///   2. runs `_preflight` — cancels any stale pending recovery with its current
///      owner (owner-aware: MainOwner or NewOwner, whichever the ping-pong
///      rotation left in charge),
///   3. re-signs fresh permissions for the live recovery nonce and acts.
/// Re-signing after preflight is mandatory: digests bind the nonce, so any
/// signature made before a startRecovery lands is dead afterwards.
abstract contract SepoliaScenarioBase is ArtifactLog {
    string internal constant LOG_DIR = "script/sepolia/logs";

    /// @dev Open a fresh artifact file under script/sepolia/logs (created if missing).
    function _initLog(string memory name) internal returns (string memory file) {
        vm.createDir(LOG_DIR, true);
        file = string.concat(LOG_DIR, "/", name);
        _artifactInit(file);
    }

    /// @dev Cancel any active pending recovery before the scenario acts. The
    /// canceller must be the account's current owner, so the signing key is
    /// resolved from live owner() (MainOwner, or NewOwner after a rotation).
    function _preflight(address account, RecoveryModule module, string memory logFile) internal {
        IERC7093.RecoveryConfigArg[] memory configs = module.getRecoveryConfigs(account);
        for (uint256 i = 0; i < configs.length; i++) {
            RecoveryModule.PendingRecovery memory pending = module.getPendingRecovery(account, i);
            if (!pending.active) continue;
            address owner = SmartAccount(payable(account)).owner();
            _artifact(
                logFile,
                string.concat(
                    "PREFLIGHT cancel stale pending nonce=",
                    vm.toString(pending.nonce),
                    " configIndex=",
                    vm.toString(i),
                    " by owner=",
                    _roleName(owner)
                )
            );
            vm.recordLogs();
            vm.broadcast(_keyForOwner(owner));
            module.cancelRecovery(account, i);
            _logRecorded(logFile);
            return;
        }
    }

    /// @dev NewOwner env pair: `NEW_OWNER_ADDR` is the on-chain-facing value
    /// (recovery target), `NEW_OWNER_KEY` only signs owner-era transactions
    /// (preflight cancels). The pairing require keeps both in sync.
    function _newOwner() internal view returns (address newOwnerAddr, uint256 newOwnerKey) {
        newOwnerAddr = vm.envAddress("NEW_OWNER_ADDR");
        newOwnerKey = vm.envUint("NEW_OWNER_KEY");
        require(vm.addr(newOwnerKey) == newOwnerAddr, "SepoliaScenario: NEW_OWNER_ADDR/KEY mismatch");
    }

    /// @dev Ping-pong target: MainOwner -> NewOwner, NewOwner -> MainOwner.
    function _toggleTarget(address account) internal view returns (address) {
        address owner = SmartAccount(payable(account)).owner();
        (address newOwnerAddr,) = _newOwner();
        if (owner == vm.envAddress("MAIN_OWNER_ADDR")) return newOwnerAddr;
        if (owner == newOwnerAddr) return vm.envAddress("MAIN_OWNER_ADDR");
        revert("SepoliaScenario: unknown owner");
    }

    /// @dev Signing key that currently controls `account`.
    function _keyForOwner(address owner) internal view returns (uint256) {
        (address newOwnerAddr, uint256 newOwnerKey) = _newOwner();
        if (owner == vm.envAddress("MAIN_OWNER_ADDR")) return vm.envUint("MAIN_OWNER_KEY");
        if (owner == newOwnerAddr) return newOwnerKey;
        revert("SepoliaScenario: unknown owner");
    }

    /// @dev Human-readable role for artifact lines.
    function _roleName(address who) internal view returns (string memory) {
        (address newOwnerAddr,) = _newOwner();
        if (who == vm.envAddress("MAIN_OWNER_ADDR")) return "MainOwner";
        if (who == newOwnerAddr) return "NewOwner";
        return vm.toString(who);
    }

    function _permEOA(bytes32 digest, uint256 key) internal pure returns (IERC7093.Permission memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return IERC7093.Permission(IERC7093.Identity(vm.addr(key), ""), abi.encodePacked(r, s, v));
    }

    function _permSCAGuardian1(bytes32 digest, address validatorAddr, address scaGuardian1Addr, uint256 scag1OwnerKey)
        internal
        pure
        returns (IERC7093.Permission memory)
    {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(scag1OwnerKey, ethHash);
        bytes memory inner = abi.encodePacked(r, s, v);
        bytes memory scaSig = abi.encodePacked(validatorAddr, inner);
        return IERC7093.Permission(IERC7093.Identity(scaGuardian1Addr, ""), scaSig);
    }
}
