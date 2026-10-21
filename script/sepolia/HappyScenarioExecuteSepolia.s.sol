// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Sepolia happy-path execute (run after the lock expires): applies the
/// pending target regardless of ping-pong direction — the expected owner is read
/// from the pending recovery itself. GUARD: refuses to broadcast before
/// `executeAfter` so the runbook fails fast instead of burning a rejected tx.
/// Transcript: `script/sepolia/logs/sep-11-happy-execute-r1.log` — EVENT lines
/// for `RecoveryExecuted` (module) and `OwnerChanged` (account) from the same tx.
contract HappyScenarioExecuteSepolia is SepoliaScenarioBase {
    function run() external {
        _artifactInit();
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));

        RecoveryModule.PendingRecovery memory pending = module.getPendingRecovery(address(mainAccount), 0);
        require(pending.active, "no active recovery");
        require(block.timestamp >= pending.executeAfter, "timelock not mature yet");

        address expectedOwner = abi.decode(pending.newOwner, (address));
        _artifact(
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
        _logRecorded(address(module), address(mainAccount));
        require(mainAccount.owner() == expectedOwner, "owner not rotated");
        _artifactEnd();
    }
}
