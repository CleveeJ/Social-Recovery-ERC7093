// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "./ArtifactLog.sol";

/// @notice Attack: a single guardian (weight 1 < threshold 2) must revert.
/// Artifact: `script/local/logs/ThresholdBypassScenario.log` — ERROR line only;
/// reverts emit no events.
contract ThresholdBypassScenario is ArtifactLog {
    string internal constant LOG_FILE = "script/local/logs/ThresholdBypassScenario.log";

    function run() external {
        _artifactInit(LOG_FILE);
        uint256 g1Key = vm.envUint("G1_KEY");
        address newOwnerAddr = vm.addr(vm.envUint("NEW_OWNER_KEY"));

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

        bytes memory newOwnerBytes = abi.encode(newOwnerAddr);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, newOwnerBytes);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(g1Key, digest);
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](1);
        perms[0] = IERC7093.Permission(IERC7093.Identity(vm.addr(g1Key), ""), abi.encodePacked(r, s, v));

        try module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms) {
            revert("threshold not enforced");
        } catch Error(string memory reason) {
            _artifactError(LOG_FILE, "ThresholdBypass solo-G1", reason);
        }
        require(!module.getPendingRecovery(address(mainAccount), 0).active, "recovery created");
        require(mainAccount.owner() == ownerBefore, "owner changed");
    }
}
