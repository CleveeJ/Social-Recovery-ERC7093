// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "./ArtifactLog.sol";

/// @notice Attack: reusing the same permissions for a second startRecovery must
/// revert (recovery nonce advanced on first start).
/// Transcript: `script/local/logs/11-replay.log` — EVENT line for the
/// legitimate first start, ERROR line for the rejected replay.
contract ReplayAttackScenario is ArtifactLog {
    function _permEOA(bytes32 digest, uint256 gKey) internal pure returns (IERC7093.Permission memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gKey, digest);
        return IERC7093.Permission(IERC7093.Identity(vm.addr(gKey), ""), abi.encodePacked(r, s, v));
    }

    function run() external {
        _artifactInit();
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");
        uint256 g1Key = vm.envUint("G1_KEY");
        uint256 g2Key = vm.envUint("G2_KEY");
        address newOwnerAddr = vm.addr(vm.envUint("NEW_OWNER_KEY"));

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

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
