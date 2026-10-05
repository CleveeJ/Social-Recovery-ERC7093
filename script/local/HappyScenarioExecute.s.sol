// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";

contract HappyScenarioExecute is Script {
    function run() external {
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");
        address newOwnerAddr = vm.addr(vm.envUint("NEW_OWNER_KEY"));

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));

        vm.broadcast(relayerKey);
        module.executeRecovery(address(mainAccount), 0);
        require(mainAccount.owner() == newOwnerAddr, "owner not rotated");

        console.log("MainOwner after (NewOwner_ADDR):", mainAccount.owner());
    }
}
