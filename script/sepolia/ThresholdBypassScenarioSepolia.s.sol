// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Attack: a single guardian (weight 1 < threshold 2) must revert,
/// even with a valid signature for the live nonce. Preflight-cancels any stale
/// pending first. Stateless: simulation only, no broadcast, no gas spent.
/// Artifact: `script/sepolia/logs/ThresholdBypassScenarioSepolia.log` — ERROR
/// line only; reverts emit no events.
contract ThresholdBypassScenarioSepolia is SepoliaScenarioBase {
    string internal constant LOG_NAME = "ThresholdBypassScenarioSepolia.log";

    function run() external {
        string memory logFile = _initLog(LOG_NAME);
        uint256 g1Key = vm.envUint("G1_KEY");
        (address newOwnerAddr,) = _newOwner();

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

        _preflight(address(mainAccount), module, logFile);

        bytes memory newOwnerBytes = abi.encode(newOwnerAddr);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, newOwnerBytes);

        IERC7093.Permission[] memory perms = new IERC7093.Permission[](1);
        perms[0] = _permEOA(digest, g1Key);

        try module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms) {
            revert("threshold not enforced");
        } catch Error(string memory reason) {
            _artifactError(logFile, "ThresholdBypass solo-G1", reason);
        }
        require(!module.getPendingRecovery(address(mainAccount), 0).active, "recovery created");
        require(mainAccount.owner() == ownerBefore, "owner changed");
    }
}
