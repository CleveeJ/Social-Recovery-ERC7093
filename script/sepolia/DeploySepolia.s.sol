// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IEntryPoint as OZEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {SmartAccount} from "../../src/SmartAccount.sol";
import {SimpleECDSAValidator} from "../../src/validators/SimpleECDSAValidator.sol";
import {RecoveryModule} from "../../src/RecoveryModule.sol";
import {SimpleThresholdPolicyVerifier} from "../../src/verifiers/SimpleThresholdPolicyVerifier.sol";
import {ArtifactLog} from "../local/ArtifactLog.sol";

/// @notice Sepolia deployment: validator + stateless verifier + RecoveryModule +
/// MainAccount (owned by MainOwner) + SCAGuardian1 (owned by SCAG1Owner, validator
/// only, no RecoveryModule). Uses the canonical EntryPoint V07 — never the local
/// forwarder. Module installation happens separately via InstallModule.s.sol
/// (genuine EntryPoint.handleOps UserOp signed by MainOwner).
///
/// Naming: MainOwner/MainAccount, G1/G2 (EOA guardians, addresses only here),
/// SCAGuardian1 (SCA), SCAG1Owner. Postfix: *_KEY = private key, *_ADDR = address.
///
/// Env inputs (all *_ADDR except DEPLOYER_KEY):
///   DEPLOYER_KEY, ENTRYPOINT_ADDR (canonical V07), MAIN_OWNER_ADDR,
///   G1_ADDR, G2_ADDR, SCAG1OWNER_ADDR.
/// Writes: script/sepolia/deployed-sepolia.env with canonical *_ADDR set.
/// Post-run (manual, funded Deployer): fund MainAccount + EntryPoint.depositTo(MainAccount),
/// then run InstallModule.s.sol to install the [G1, G2, SCAGuardian1] config.
contract DeploySepolia is ArtifactLog {
    string internal constant LOG_FILE = "script/local/logs/DeploySepolia.log";
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address entryPointAddr = vm.envAddress("ENTRYPOINT_ADDR");
        address mainOwnerAddr = vm.envAddress("MAIN_OWNER_ADDR");
        address g1Addr = vm.envAddress("G1_ADDR");
        address g2Addr = vm.envAddress("G2_ADDR");
        address scag1OwnerAddr = vm.envAddress("SCAG1OWNER_ADDR");

        vm.startBroadcast(deployerKey);
        SimpleECDSAValidator validator = new SimpleECDSAValidator();
        SimpleThresholdPolicyVerifier verifier = new SimpleThresholdPolicyVerifier();
        RecoveryModule module = new RecoveryModule();
        SmartAccount mainAccount = new SmartAccount(OZEntryPoint(entryPointAddr), mainOwnerAddr);
        mainAccount.initializeAccount(address(validator), "");

        SmartAccount scaGuardian1 = new SmartAccount(OZEntryPoint(entryPointAddr), scag1OwnerAddr);
        scaGuardian1.initializeAccount(address(validator), "");
        vm.stopBroadcast();

        // Constructors emit no events: addresses are the artifact (no-event case).
        _artifactInit(LOG_FILE);
        _artifact(LOG_FILE, string.concat("DEPLOY EntryPoint=", vm.toString(entryPointAddr)));
        _artifact(LOG_FILE, string.concat("DEPLOY Validator=", vm.toString(address(validator))));
        _artifact(LOG_FILE, string.concat("DEPLOY PolicyVerifier=", vm.toString(address(verifier))));
        _artifact(LOG_FILE, string.concat("DEPLOY RecoveryModule=", vm.toString(address(module))));
        _artifact(LOG_FILE, string.concat("DEPLOY MainAccount=", vm.toString(address(mainAccount))));
        _artifact(LOG_FILE, string.concat("DEPLOY MainOwner_ADDR=", vm.toString(mainOwnerAddr)));
        _artifact(LOG_FILE, string.concat("DEPLOY G1_ADDR=", vm.toString(g1Addr)));
        _artifact(LOG_FILE, string.concat("DEPLOY G2_ADDR=", vm.toString(g2Addr)));
        _artifact(LOG_FILE, string.concat("DEPLOY SCAGuardian1_ADDR=", vm.toString(address(scaGuardian1))));
        _artifact(LOG_FILE, string.concat("DEPLOY SCAG1Owner_ADDR=", vm.toString(scag1OwnerAddr)));

        string memory envPath = "script/sepolia/deployed-sepolia.env";
        vm.writeFile(envPath, string.concat("ENTRYPOINT_ADDR=", vm.toString(entryPointAddr), "\n"));
        vm.writeLine(envPath, string.concat("VALIDATOR_ADDR=", vm.toString(address(validator))));
        vm.writeLine(envPath, string.concat("VERIFIER_ADDR=", vm.toString(address(verifier))));
        vm.writeLine(envPath, string.concat("MODULE_ADDR=", vm.toString(address(module))));
        vm.writeLine(envPath, string.concat("MAIN_ACCOUNT_ADDR=", vm.toString(address(mainAccount))));
        vm.writeLine(envPath, string.concat("MAIN_OWNER_ADDR=", vm.toString(mainOwnerAddr)));
        vm.writeLine(envPath, string.concat("G1_ADDR=", vm.toString(g1Addr)));
        vm.writeLine(envPath, string.concat("G2_ADDR=", vm.toString(g2Addr)));
        vm.writeLine(envPath, string.concat("SCAGUARDIAN1_ADDR=", vm.toString(address(scaGuardian1))));
        vm.writeLine(envPath, string.concat("SCAG1OWNER_ADDR=", vm.toString(scag1OwnerAddr)));
    }
}
