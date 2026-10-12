// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "./ArtifactLog.sol";

/// @notice Attack: G1 plus an unregistered stranger must revert.
/// Artifact: `script/local/logs/UnregisteredGuardianScenario.log` — ERROR line
contract UnregisteredGuardianScenario is ArtifactLog {
    string internal constant LOG_FILE = "script/local/logs/UnregisteredGuardianScenario.log";

    uint256 constant STRANGER_KEY = 0x9999999999999999999999999999999999999999999999999999999999999999;

    function _permEOA(bytes32 digest, uint256 gKey) internal pure returns (IERC7093.Permission memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gKey, digest);
        return IERC7093.Permission(IERC7093.Identity(vm.addr(gKey), ""), abi.encodePacked(r, s, v));
    }

    function run() external {
        _artifactInit(LOG_FILE);
        uint256 g1Key = vm.envUint("G1_KEY");
        address newOwnerAddr = vm.addr(vm.envUint("NEW_OWNER_KEY"));

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

        bytes memory newOwnerBytes = abi.encode(newOwnerAddr);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, newOwnerBytes);
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](2);
        perms[0] = _permEOA(digest, g1Key);
        perms[1] = _permEOA(digest, STRANGER_KEY);

        try module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms) {
            revert("stranger not rejected");
        } catch Error(string memory reason) {
            _artifactError(LOG_FILE, "UnregisteredGuardian G1+stranger", reason);
        }
        require(!module.getPendingRecovery(address(mainAccount), 0).active, "recovery created");
        require(mainAccount.owner() == ownerBefore, "owner changed");
    }
}
