// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IEntryPoint as OZEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {SmartAccount} from "../../src/SmartAccount.sol";
import {SimpleECDSAValidator} from "../../src/validators/SimpleECDSAValidator.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {SimpleThresholdPolicyVerifier} from "../../src/verifiers/SimpleThresholdPolicyVerifier.sol";
import {IERC7093} from "../../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "./ArtifactLog.sol";

/// @notice Minimal local stand-in for the EntryPoint: only forwards module
/// installation so the account's `onlyEntryPointOrSelf` gate passes on Anvil.
/// (Live nets reuse the canonical EntryPoint instead; see InstallModuleSepolia.s.sol.)
contract LocalEntryPoint {
    function installFor(address account, uint256 moduleTypeId, address module, bytes calldata initData) external {
        SmartAccount(payable(account)).installModule(moduleTypeId, module, initData);
    }
}

/// @notice Local Anvil deployment: forwarder EntryPoint + validator + stateless
/// verifier + RecoveryModule + MainAccount, with validator installed at init
/// and the executor installed with a 2-of-3 demo config [G1, G2, SCAGuardian1].
/// SCAGuardian1 is a second SmartAccount (owned by SCAG1Owner)
/// with only the validator installed (no RecoveryModule). Writes addresses to
/// `script/local/deployed-local.env` for the scenario scripts.
///
/// Naming: MainOwner/MainAccount, G1/G2 (EOA), SCAGuardian1 (SCA),
/// SCAG1Owner (EOA owner of SCAGuardian1), NewOwner.
/// Postfix discipline: *_KEY = private key (vm.envUint), *_ADDR = address (vm.envAddress).
contract DeployLocal is ArtifactLog {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        uint256 mainOwnerKey = vm.envUint("MAIN_OWNER_KEY");
        address mainOwnerAddr = vm.addr(mainOwnerKey);

        address g1Addr = vm.addr(vm.envUint("G1_KEY"));
        address g2Addr = vm.addr(vm.envUint("G2_KEY"));
        uint256 scag1OwnerKey = vm.envUint("SCAG1OWNER_KEY");
        address scag1OwnerAddr = vm.addr(scag1OwnerKey);
        uint64 threshold = uint64(vm.envUint("DEMO_THRESHOLD"));
        uint256 lockSeconds = vm.envUint("DEMO_LOCK_SECONDS");

        vm.startBroadcast(deployerKey);
        LocalEntryPoint entryPoint = new LocalEntryPoint();
        SimpleECDSAValidator validator = new SimpleECDSAValidator();
        SimpleThresholdPolicyVerifier verifier = new SimpleThresholdPolicyVerifier();
        RecoveryModule module = new RecoveryModule();
        SmartAccount mainAccount = new SmartAccount(OZEntryPoint(address(entryPoint)), mainOwnerAddr);

        // SCAGuardian1: second SmartAccount owned by SCAG1Owner, validator only.
        SmartAccount scaGuardian1 = new SmartAccount(OZEntryPoint(address(entryPoint)), scag1OwnerAddr);

        if (mainOwnerAddr.balance < 0.001 ether) {
            (bool ok,) = payable(mainOwnerAddr).call{value: 1 ether}("");
            require(ok, "fund main owner failed");
        }
        if (scag1OwnerAddr.balance < 0.001 ether) {
            (bool ok,) = payable(scag1OwnerAddr).call{value: 1 ether}("");
            require(ok, "fund scag1 owner failed");
        }
        vm.stopBroadcast();

        vm.startBroadcast(mainOwnerKey);
        mainAccount.initializeAccount(address(validator), "");
        vm.stopBroadcast();

        vm.startBroadcast(scag1OwnerKey);
        scaGuardian1.initializeAccount(address(validator), "");
        vm.stopBroadcast();

        IERC7093.GuardianInfo[] memory guardians = new IERC7093.GuardianInfo[](3);
        guardians[0] = IERC7093.GuardianInfo(IERC7093.Identity(g1Addr, ""), 1);
        guardians[1] = IERC7093.GuardianInfo(IERC7093.Identity(g2Addr, ""), 1);
        guardians[2] = IERC7093.GuardianInfo(IERC7093.Identity(address(scaGuardian1), ""), 1);
        IERC7093.ThresholdConfig[] memory tiers = new IERC7093.ThresholdConfig[](1);
        tiers[0] = IERC7093.ThresholdConfig(threshold, int48(uint48(lockSeconds)));
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(verifier), guardians, tiers);

        vm.startBroadcast(deployerKey);
        entryPoint.installFor(address(mainAccount), MODULE_TYPE_EXECUTOR, address(module), abi.encode(args));
        vm.stopBroadcast();

        require(mainAccount.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module), ""), "module not installed");

        // Constructors emit no events: addresses are the artifact (no-event case).
        _artifactInit();
        _artifact(string.concat("DEPLOY EntryPoint=", vm.toString(address(entryPoint))));
        _artifact(string.concat("DEPLOY Validator=", vm.toString(address(validator))));
        _artifact(string.concat("DEPLOY PolicyVerifier=", vm.toString(address(verifier))));
        _artifact(string.concat("DEPLOY RecoveryModule=", vm.toString(address(module))));
        _artifact(string.concat("DEPLOY MainAccount=", vm.toString(address(mainAccount))));
        _artifact(string.concat("DEPLOY MainOwner_ADDR=", vm.toString(mainOwnerAddr)));
        _artifact(string.concat("DEPLOY G1_ADDR=", vm.toString(g1Addr)));
        _artifact(string.concat("DEPLOY G2_ADDR=", vm.toString(g2Addr)));
        _artifact(string.concat("DEPLOY SCAGuardian1_ADDR=", vm.toString(address(scaGuardian1))));
        _artifact(string.concat("DEPLOY SCAG1Owner_ADDR=", vm.toString(scag1OwnerAddr)));

        string memory envPath = "script/local/deployed-local.env";
        vm.writeFile(envPath, string.concat("ENTRYPOINT_ADDR=", vm.toString(address(entryPoint)), "\n"));
        vm.writeLine(envPath, string.concat("VALIDATOR_ADDR=", vm.toString(address(validator))));
        vm.writeLine(envPath, string.concat("VERIFIER_ADDR=", vm.toString(address(verifier))));
        vm.writeLine(envPath, string.concat("MODULE_ADDR=", vm.toString(address(module))));
        vm.writeLine(envPath, string.concat("MAIN_ACCOUNT_ADDR=", vm.toString(address(mainAccount))));
        vm.writeLine(envPath, string.concat("MAIN_OWNER_ADDR=", vm.toString(mainOwnerAddr)));
        vm.writeLine(envPath, string.concat("G1_ADDR=", vm.toString(g1Addr)));
        vm.writeLine(envPath, string.concat("G2_ADDR=", vm.toString(g2Addr)));
        vm.writeLine(envPath, string.concat("SCAGUARDIAN1_ADDR=", vm.toString(address(scaGuardian1))));
        vm.writeLine(envPath, string.concat("SCAG1OWNER_ADDR=", vm.toString(scag1OwnerAddr)));
        _artifactEnd();
    }
}
