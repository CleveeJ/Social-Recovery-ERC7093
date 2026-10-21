// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";

/// @notice Shared logger for scenario scripts: the single place where
/// `console.log` is allowed. The runbooks capture stdout per command into
/// `script/local/logs/<nn>-<step>.log` or `script/sepolia/logs/sep-<nn>-<step>.log`,
/// so every line printed here becomes the evidence transcript (no extra files).
///
/// Rule: success evidence comes from decoded on-chain events (caught via
/// `vm.recordLogs()` / `vm.getRecordedLogs()` around the broadcast call);
/// failure evidence comes from caught revert reasons (reverts roll back logs,
/// and EIP-7093 defines no errors — Security Considerations: "Needs discussion").
/// Logs are written during the simulation phase: the header marks
/// `mode=simulation`, and receipts/broadcast JSON remain the on-chain truth.
abstract contract ArtifactLog is Script {
    bytes32 internal constant RECOVERY_STARTED_TOPIC = keccak256("RecoveryStarted(bytes,uint256,uint48)");
    bytes32 internal constant RECOVERY_EXECUTED_TOPIC = keccak256("RecoveryExecuted(bytes,uint256)");
    bytes32 internal constant RECOVERY_CANCELED_TOPIC = keccak256("RecoveryCanceled(uint256)");
    bytes32 internal constant RECOVERY_CONFIGURED_TOPIC =
        keccak256("RecoveryConfigured(address,uint256,address)");
    bytes32 internal constant OWNER_CHANGED_TOPIC = keccak256("OwnerChanged(address)");

    /// @dev Print run metadata at the start of a scenario. `simBlock`/
    /// `simTimestamp` describe the simulation state, not the mined transaction:
    /// receipts/broadcast JSON remain the chain truth. `END status=ok` (from
    /// `_artifactEnd`) must appear at the bottom of a successful run.
    function _artifactInit() internal {
        console.log(
            string.concat(
                "RUN chainId=",
                vm.toString(block.chainid),
                " simBlock=",
                vm.toString(block.number),
                " simTimestamp=",
                vm.toString(block.timestamp),
                " mode=simulation"
            )
        );
    }

    /// @dev Mark a completed run: every post-condition passed in simulation.
    function _artifactEnd() internal {
        _artifact("END status=ok");
    }

    /// @dev The only console.log wrapper: runbooks tee stdout into the evidence log.
    function _artifact(string memory line) internal {
        console.log(line);
    }

    /// @dev Log a caught revert reason (no event can exist on reverted paths).
    function _artifactError(string memory context, string memory reason) internal {
        _artifact(string.concat("ERROR context=\"", context, "\" reason=\"", reason, "\""));
    }

    /// @dev Render a Panic code as a loggable reason.
    function _panicReason(uint256 code) internal view returns (string memory) {
        return string.concat("panic code=", vm.toString(code));
    }

    /// @dev Render raw revert data (custom error selector + args) as a loggable reason.
    function _customReason(bytes memory data) internal view returns (string memory) {
        return string.concat("custom-error ", vm.toString(data));
    }

    /// @dev Decode recorded logs emitted by `emitter` since `vm.recordLogs()`
    /// into artifact lines. Unknown topics are skipped.
    function _logRecorded(address emitter) internal {
        _logRecorded(emitter, address(0));
    }

    /// @dev Same as the single-emitter variant, but accepts two known emitters
    /// (e.g. RecoveryModule + SmartAccount in the same execute transaction).
    function _logRecorded(address emitterA, address emitterB) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length == 0) continue;
            if (logs[i].emitter != emitterA && logs[i].emitter != emitterB) continue;
            bytes32 t0 = logs[i].topics[0];
            if (t0 == RECOVERY_STARTED_TOPIC) {
                (bytes memory newOwners, uint256 nonce, uint48 executeAfter) =
                    abi.decode(logs[i].data, (bytes, uint256, uint48));
                _artifact(
                    string.concat(
                        "EVENT RecoveryStarted newOwner=",
                        vm.toString(abi.decode(newOwners, (address))),
                        " nonce=",
                        vm.toString(nonce),
                        " executeAfter=",
                        vm.toString(uint256(executeAfter))
                    )
                );
            } else if (t0 == RECOVERY_EXECUTED_TOPIC) {
                (bytes memory newOwners, uint256 nonce) = abi.decode(logs[i].data, (bytes, uint256));
                _artifact(
                    string.concat(
                        "EVENT RecoveryExecuted newOwner=",
                        vm.toString(abi.decode(newOwners, (address))),
                        " nonce=",
                        vm.toString(nonce)
                    )
                );
            } else if (t0 == RECOVERY_CANCELED_TOPIC) {
                (uint256 nonce) = abi.decode(logs[i].data, (uint256));
                _artifact(string.concat("EVENT RecoveryCanceled nonce=", vm.toString(nonce)));
            } else if (t0 == RECOVERY_CONFIGURED_TOPIC) {
                address account = address(uint160(uint256(logs[i].topics[1])));
                uint256 configIndex = uint256(logs[i].topics[2]);
                address verifier = address(uint160(uint256(logs[i].topics[3])));
                _artifact(
                    string.concat(
                        "EVENT RecoveryConfigured account=",
                        vm.toString(account),
                        " configIndex=",
                        vm.toString(configIndex),
                        " verifier=",
                        vm.toString(verifier)
                    )
                );
            } else if (t0 == OWNER_CHANGED_TOPIC) {
                address newOwner = address(uint160(uint256(logs[i].topics[1])));
                _artifact(string.concat("EVENT OwnerChanged newOwner=", vm.toString(newOwner)));
            }
        }
    }
}
