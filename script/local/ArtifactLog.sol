// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";

/// @notice Shared artifact logger for scenario scripts: single place where
/// `console.log` is allowed. Every printed line is also appended to a
/// per-scenario artifact file under `script/local/logs/` for thesis evidence.
///
/// Rule: success evidence comes from decoded on-chain events (caught via
/// `vm.recordLogs()` / `vm.getRecordedLogs()` around the broadcast call);
/// failure evidence comes from caught revert reasons (reverts roll back logs,
/// and EIP-7093 defines no errors — Security Considerations: "Needs discussion").
abstract contract ArtifactLog is Script {
    bytes32 internal constant RECOVERY_STARTED_TOPIC = keccak256("RecoveryStarted(bytes,uint256,uint48)");
    bytes32 internal constant RECOVERY_EXECUTED_TOPIC = keccak256("RecoveryExecuted(bytes,uint256)");
    bytes32 internal constant RECOVERY_CANCELED_TOPIC = keccak256("RecoveryCanceled(uint256)");
    bytes32 internal constant RECOVERY_CONFIGURED_TOPIC =
        keccak256("RecoveryConfigured(address,uint256,address)");
    bytes32 internal constant OWNER_CHANGED_TOPIC = keccak256("OwnerChanged(address)");

    /// @dev Start a fresh artifact file (overwrites previous runs).
    function _artifactInit(string memory file) internal {
        vm.writeFile(file, "SCENARIO ARTIFACT LOG\n");
    }

    /// @dev The only console.log wrapper: terminal line + artifact file line.
    function _artifact(string memory file, string memory line) internal {
        console.log(line);
        vm.writeLine(file, line);
    }

    /// @dev Log a caught revert reason (no event can exist on reverted paths).
    function _artifactError(string memory file, string memory context, string memory reason) internal {
        _artifact(file, string.concat("ERROR ", context, " reverted: ", reason));
    }

    /// @dev Decode all recorded logs since `vm.recordLogs()` into artifact lines.
    /// Unknown emitters/topics are skipped; known events are printed human-readable.
    function _logRecorded(string memory file) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length == 0) continue;
            bytes32 t0 = logs[i].topics[0];
            if (t0 == RECOVERY_STARTED_TOPIC) {
                (bytes memory newOwners, uint256 nonce, uint48 executeAfter) =
                    abi.decode(logs[i].data, (bytes, uint256, uint48));
                _artifact(
                    file,
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
                    file,
                    string.concat(
                        "EVENT RecoveryExecuted newOwner=",
                        vm.toString(abi.decode(newOwners, (address))),
                        " nonce=",
                        vm.toString(nonce)
                    )
                );
            } else if (t0 == RECOVERY_CANCELED_TOPIC) {
                (uint256 nonce) = abi.decode(logs[i].data, (uint256));
                _artifact(file, string.concat("EVENT RecoveryCanceled nonce=", vm.toString(nonce)));
            } else if (t0 == RECOVERY_CONFIGURED_TOPIC) {
                address account = address(uint160(uint256(logs[i].topics[1])));
                uint256 configIndex = uint256(logs[i].topics[2]);
                address verifier = address(uint160(uint256(logs[i].topics[3])));
                _artifact(
                    file,
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
                _artifact(file, string.concat("EVENT OwnerChanged newOwner=", vm.toString(newOwner)));
            }
        }
    }
}
