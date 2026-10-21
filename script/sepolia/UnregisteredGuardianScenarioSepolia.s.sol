// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Attack: G1 plus an unregistered stranger must revert even though two
/// signatures are present (the stranger carries no weight). Preflight-cancels any
/// stale pending first. Stateless: simulation only, no broadcast, no gas spent.
/// Transcript: `script/sepolia/logs/sep-31-stranger.log` — ERROR line.
contract UnregisteredGuardianScenarioSepolia is SepoliaScenarioBase {
    uint256 constant STRANGER_KEY = uint256(keccak256("social-recovery.stranger"));

    function run() external {
        _artifactInit();
        uint256 g1Key = vm.envUint("G1_KEY");
        (address newOwnerAddr,) = _newOwner();

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

        _preflight(address(mainAccount), module);

        bytes memory newOwnerBytes = abi.encode(newOwnerAddr);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, newOwnerBytes);
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](2);
        perms[0] = _permEOA(digest, g1Key);
        perms[1] = _permEOA(digest, STRANGER_KEY);

        try module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms) {
            revert("stranger not rejected");
        } catch Error(string memory reason) {
            _artifactError("UnregisteredGuardian G1+stranger", reason);
        } catch Panic(uint256 code) {
            _artifactError("UnregisteredGuardian G1+stranger", _panicReason(code));
        } catch (bytes memory data) {
            _artifactError("UnregisteredGuardian G1+stranger", _customReason(data));
        }
        require(!module.getPendingRecovery(address(mainAccount), 0).active, "recovery created");
        require(mainAccount.owner() == ownerBefore, "owner changed");
        _artifactEnd();
    }
}
