// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Attack: reusing the same permissions for a second startRecovery must
/// revert (the recovery nonce advanced on first start; preflight cancellations do
/// not burn the nonce). Preflight-cancels any stale pending, starts a legitimate
/// recovery (G1 + G2), then replays the exact same permission bytes.
/// Transcript: `script/sepolia/logs/sep-24-replay.log` — EVENT line
/// for the legitimate first start, ERROR line for the rejected replay.
contract ReplayAttackScenarioSepolia is SepoliaScenarioBase {
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

        try module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms) {
            revert("replay not rejected");
        } catch Error(string memory reason) {
            _artifactError("ReplayAttack", reason);
        } catch Panic(uint256 code) {
            _artifactError("ReplayAttack", _panicReason(code));
        } catch (bytes memory data) {
            _artifactError("ReplayAttack", _customReason(data));
        }
        require(mainAccount.owner() == ownerBefore, "owner changed");
        _artifactEnd();
    }
}
