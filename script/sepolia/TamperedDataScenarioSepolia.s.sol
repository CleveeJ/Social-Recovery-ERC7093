// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SmartAccount} from "../../src/SmartAccount.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {SepoliaScenarioBase} from "./SepoliaScenarioBase.sol";

/// @notice Attack: valid guardian signatures submitted for tampered newOwner bytes
/// must revert (the digest binds newOwner). Preflight-cancels any stale pending,
/// signs the real target (G1 + G2), then submits different bytes in the same call.
/// Stateless: simulation only, no broadcast, no gas spent.
/// Transcript: `script/sepolia/logs/sep-22-tamper.log` — ERROR line only.
contract TamperedDataScenarioSepolia is SepoliaScenarioBase {
    function run() external {
        _artifactInit();
        uint256 g1Key = vm.envUint("G1_KEY");
        uint256 g2Key = vm.envUint("G2_KEY");
        (address newOwnerAddr,) = _newOwner();

        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address ownerBefore = mainAccount.owner();

        _preflight(address(mainAccount), module);

        bytes memory signedBytes = abi.encode(newOwnerAddr);
        bytes32 digest = module.getRecoveryDigest(address(mainAccount), 0, signedBytes);
        IERC7093.Permission[] memory perms = new IERC7093.Permission[](2);
        perms[0] = _permEOA(digest, g1Key);
        perms[1] = _permEOA(digest, g2Key);

        bytes memory tamperedBytes = abi.encode(address(0x1234));

        try module.startRecovery(address(mainAccount), 0, tamperedBytes, perms) {
            revert("tamper not rejected");
        } catch Error(string memory reason) {
            _artifactError("TamperedData", reason);
        } catch Panic(uint256 code) {
            _artifactError("TamperedData", _panicReason(code));
        } catch (bytes memory data) {
            _artifactError("TamperedData", _customReason(data));
        }
        require(!module.getPendingRecovery(address(mainAccount), 0).active, "recovery created");
        require(mainAccount.owner() == ownerBefore, "owner changed");
        _artifactEnd();
    }
}
