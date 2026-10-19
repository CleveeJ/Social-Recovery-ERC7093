// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Sepolia happy-path execute (run after the lock expires): applies the
/// pending target regardless of ping-pong direction — the expected owner is read
/// from the pending recovery itself. GUARD: refuses to broadcast before
/// `executeAfter` so the runbook fails fast instead of burning a rejected tx.
/// Artifact: `script/sepolia/logs/HappyScenarioExecuteSepolia.log` — EVENT lines
/// for `RecoveryExecuted` (module) and `OwnerChanged` (account) from the same tx.
contract HappyScenarioExecuteSepolia is SepoliaScenarioBase {
    string internal constant LOG_NAME = "HappyScenarioExecuteSepolia.log";

    function run() external {
        string memory logFile = _initLog(LOG_NAME);
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));

        RecoveryModule.PendingRecovery memory pending = module.getPendingRecovery(address(mainAccount), 0);
        require(pending.active, "no active recovery");
        require(block.timestamp >= pending.executeAfter, "timelock not mature yet");

        address expectedOwner = abi.decode(pending.newOwner, (address));
        _artifact(
            logFile,
            string.concat(
                "EXECUTE pending nonce=",
                vm.toString(pending.nonce),
                " expectedOwner=",
                _roleName(expectedOwner)
            )
        );

        vm.recordLogs();
        vm.broadcast(relayerKey);
        module.executeRecovery(address(mainAccount), 0);
        _logRecorded(logFile);
        require(mainAccount.owner() == expectedOwner, "owner not rotated");
    }
}
