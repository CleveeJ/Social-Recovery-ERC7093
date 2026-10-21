// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Attack: execute before the lock expires must revert. Preflight-cancels
/// any stale pending, then starts a legitimate recovery (G1 + G2) so the early
/// execute attempt has a live target to fail against. The pending is left behind
/// on purpose — the next scenario's preflight (or the owner) cancels it.
/// Transcript: `script/sepolia/logs/sep-40-timelock.log` — EVENT line
/// for the setup `RecoveryStarted`, ERROR line with the caught timelock reason.
contract TimeLockBypassScenarioSepolia is SepoliaScenarioBase {
    function run() external {
        _artifactInit();
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");
        uint256 g1Key = vm.envUint("G1_KEY");
        uint256 g2Key = vm.envUint("G2_KEY");
        (address newOwnerAddr,) = _newOwner();

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

        _preflight(address(mainAccount), module);

        bytes memory newOwnerBytes = abi.encode(newOwnerAddr);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, newOwnerBytes);
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](2);
        perms[0] = _permEOA(digest, g1Key);
        perms[1] = _permEOA(digest, g2Key);

        vm.recordLogs();
        vm.broadcast(relayerKey);
        module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms);
        _logRecorded(address(module));
        require(module.getPendingRecovery(address(mainAccount), 0).active, "not pending");

        try module.executeRecovery(address(mainAccount), 0) {
            revert("timelock not enforced");
        } catch Error(string memory reason) {
            _artifactError("TimeLockBypass", reason);
        } catch Panic(uint256 code) {
            _artifactError("TimeLockBypass", _panicReason(code));
        } catch (bytes memory data) {
            _artifactError("TimeLockBypass", _customReason(data));
        }
        require(mainAccount.owner() == ownerBefore, "owner changed");
        _artifactEnd();
    }
}
