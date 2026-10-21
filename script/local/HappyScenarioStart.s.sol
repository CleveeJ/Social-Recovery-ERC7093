// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "./ArtifactLog.sol";

/// @notice Happy-path start: G1 (EOA) + SCAGuardian1 (SCA) reach 2-of-3 quorum.
/// Transcript: `script/local/logs/01-happy-start.log` — EVENT lines decoded
/// from recorded on-chain logs, ERROR line from the caught timelock revert
/// (reverts emit no events; EIP-7093 defines no errors).
contract HappyScenarioStart is ArtifactLog {
    function _permEOA(bytes32 digest, uint256 gKey) internal pure returns (IERC7093.Permission memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gKey, digest);
        return IERC7093.Permission(IERC7093.Identity(vm.addr(gKey), ""), abi.encodePacked(r, s, v));
    }

    function _permSCAGuardian1(bytes32 digest, address validatorAddr, address scaGuardian1Addr, uint256 scag1OwnerKey)
        internal
        pure
        returns (IERC7093.Permission memory)
    {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(scag1OwnerKey, ethHash);
        bytes memory inner = abi.encodePacked(r, s, v);
        bytes memory scaSig = abi.encodePacked(validatorAddr, inner);
        return IERC7093.Permission(IERC7093.Identity(scaGuardian1Addr, ""), scaSig);
    }

    function run() external {
        _artifactInit();
        uint256 relayerKey = vm.envUint("DEPLOYER_KEY");
        uint256 g1Key = vm.envUint("G1_KEY");
        uint256 scag1OwnerKey = vm.envUint("SCAG1OWNER_KEY");
        address newOwnerAddr = vm.addr(vm.envUint("NEW_OWNER_KEY"));

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address validatorAddr = vm.envAddress("VALIDATOR_ADDR");
        address scaGuardian1Addr = vm.envAddress("SCAGUARDIAN1_ADDR");

        bytes memory newOwnerBytes = abi.encode(newOwnerAddr);
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
