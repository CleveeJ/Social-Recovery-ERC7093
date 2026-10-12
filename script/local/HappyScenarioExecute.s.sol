// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {ArtifactLog} from "./ArtifactLog.sol";

/// @notice Happy-path execute (run after the lock expires): applies NewOwner.
/// Artifact: `script/local/logs/HappyScenarioExecute.log` — EVENT lines for
/// `RecoveryExecuted` (module) and `OwnerChanged` (account) from the same tx.
contract HappyScenarioExecute is ArtifactLog {
    string internal constant LOG_FILE = "script/local/logs/HappyScenarioExecute.log";

    function run() external {
        _artifactInit(LOG_FILE);
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");
        address newOwnerAddr = vm.addr(vm.envUint("NEW_OWNER_KEY"));

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));

        vm.recordLogs();
        vm.broadcast(relayerKey);
        module.executeRecovery(address(mainAccount), 0);
        _logRecorded(LOG_FILE);
        require(mainAccount.owner() == newOwnerAddr, "owner not rotated");
    }
}
