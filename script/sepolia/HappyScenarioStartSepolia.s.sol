// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Sepolia happy-path start (ping-pong): recovers from the current owner
/// to the other one — MainOwner -> NewOwner, or NewOwner -> MainOwner after a
/// previous rotation. Preflight-cancels any stale pending (owner-aware), re-signs
/// with the live nonce (G1 + SCAGuardian1, 2-of-3 quorum), starts the recovery,
/// then proves the early execute is blocked by the timelock.
/// Transcript: `script/sepolia/logs/sep-10-happy-start-r1.log` — DIRECTION line,
/// EVENT lines decoded from recorded logs, ERROR line from the caught revert.
contract HappyScenarioStartSepolia is SepoliaScenarioBase {
    function run() external {
        _artifactInit();
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");
        uint256 g1Key = vm.envUint("G1_KEY");
        uint256 scag1OwnerKey = vm.envUint("SCAG1OWNER_KEY");

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address validatorAddr = vm.envAddress("VALIDATOR_ADDR");
        address scaGuardian1Addr = vm.envAddress("SCAGUARDIAN1_ADDR");

        _preflight(address(mainAccount), module);

        address ownerBefore = mainAccount.owner();
        address target = _toggleTarget(address(mainAccount));
        _artifact(
            string.concat(
                "DIRECTION ",
                _roleName(ownerBefore),
                " -> ",
                _roleName(target),
                " nonce=",
                vm.toString(module.getRecoveryNonce(address(mainAccount)))
            )
        );

        bytes memory newOwnerBytes = abi.encode(target);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, newOwnerBytes);
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](2);
        perms[0] = _permEOA(digest, g1Key);
        perms[1] = _permSCAGuardian1(digest, validatorAddr, scaGuardian1Addr, scag1OwnerKey);

        vm.recordLogs();
        vm.broadcast(relayerKey);
        module.startRecovery(address(mainAccount), 0, newOwnerBytes, perms);
        _logRecorded(address(module));
        require(module.getPendingRecovery(address(mainAccount), 0).active, "not pending");

        try module.executeRecovery(address(mainAccount), 0) {
            revert("timelock not enforced");
        } catch Error(string memory reason) {
            _artifactError("EarlyExecute", reason);
        } catch Panic(uint256 code) {
            _artifactError("EarlyExecute", _panicReason(code));
        } catch (bytes memory data) {
            _artifactError("EarlyExecute", _customReason(data));
        }
        _artifactEnd();
    }
}
