// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Attack: G1 plus an unregistered stranger must revert even though two
/// signatures are present (the stranger carries no weight). Preflight-cancels any
/// stale pending first. Stateless: simulation only, no broadcast, no gas spent.
/// Artifact: `script/sepolia/logs/UnregisteredGuardianScenarioSepolia.log` — ERROR line.
contract UnregisteredGuardianScenarioSepolia is SepoliaScenarioBase {
    string internal constant LOG_NAME = "UnregisteredGuardianScenarioSepolia.log";

    uint256 constant STRANGER_KEY = 0x9999999999999999999999999999999999999999999999999999999999999999;

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
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](2);
        perms[0] = _permEOA(digest, g1Key);
        perms[1] = _permEOA(digest, STRANGER_KEY);

        try module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms) {
            revert("stranger not rejected");
        } catch Error(string memory reason) {
            _artifactError(logFile, "UnregisteredGuardian G1+stranger", reason);
        }
        require(!module.getPendingRecovery(address(mainAccount), 0).active, "recovery created");
        require(mainAccount.owner() == ownerBefore, "owner changed");
    }
}
