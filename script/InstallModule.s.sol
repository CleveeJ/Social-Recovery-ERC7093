// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {SmartAccount} from "../src/SmartAccount.sol";
import {RecoveryModule} from "../src/RecoveryModule.sol";
import {IERC7093} from "../src/interfaces/IERC7093.sol";
import {ArtifactLog} from "./local/ArtifactLog.sol";

/// @notice Installs the RecoveryModule executor via a genuine EntryPoint.handleOps
/// UserOp signed by MainOwner. Reads deployed addresses from the environment
/// (export them from the DeploySepolia log first). Requires MainAccount funded and
/// its EntryPoint deposit topped up (see README flow with cast).
///
/// Naming: MainOwner/MainAccount, G1/G2 (EOA), SCAGuardian1 (SCA, validator only,
/// no module). Postfix: *_KEY = private key, *_ADDR = address.
/// SCAGuardian1 must already be deployed + validator-initialized before running.
///
/// Artifact: `script/local/logs/InstallModule.log` — EVENT line for the
/// `RecoveryConfigured` emitted during `onInstall` inside `handleOps`.
contract InstallModule is ArtifactLog {
    string internal constant LOG_FILE = "script/local/logs/InstallModule.log";
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        uint256 mainOwnerKey = vm.envUint("MAIN_OWNER_KEY");
        address payable beneficiary = payable(vm.addr(deployerKey));

        EntryPoint entryPoint = EntryPoint(payable(vm.envAddress("ENTRYPOINT_ADDR")));
        SmartAccount mainAccount = SmartAccount(payable(vm.envAddress("MAIN_ACCOUNT_ADDR")));
        address validator = vm.envAddress("VALIDATOR_ADDR");
        RecoveryModule module = RecoveryModule(vm.envAddress("MODULE_ADDR"));
        address verifier = vm.envAddress("VERIFIER_ADDR");

        address g1Addr = vm.envAddress("G1_ADDR");
        address g2Addr = vm.envAddress("G2_ADDR");
        address scaGuardian1Addr = vm.envAddress("SCAGUARDIAN1_ADDR");
        uint64 threshold = uint64(vm.envUint("DEMO_THRESHOLD"));
        uint256 lockSeconds = vm.envUint("DEMO_LOCK_SECONDS");

        IERC7093.GuardianInfo[] memory guardians = new IERC7093.GuardianInfo[](3);
        guardians[0] = IERC7093.GuardianInfo(IERC7093.Identity(g1Addr, ""), 1);
        guardians[1] = IERC7093.GuardianInfo(IERC7093.Identity(g2Addr, ""), 1);
        guardians[2] = IERC7093.GuardianInfo(IERC7093.Identity(scaGuardian1Addr, ""), 1);
        IERC7093.ThresholdConfig[] memory tiers = new IERC7093.ThresholdConfig[](1);
        tiers[0] = IERC7093.ThresholdConfig(threshold, int48(uint48(lockSeconds)));
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(verifier), guardians, tiers);

        bytes memory installCalldata =
            abi.encodeCall(mainAccount.installModule, (MODULE_TYPE_EXECUTOR, address(module), abi.encode(args)));
        PackedUserOperation memory op;
        op.sender = address(mainAccount);
        op.nonce = (uint256(uint160(validator)) << 96);
        op.callData = installCalldata;
        op.accountGasLimits = bytes32((uint256(500_000) << 128) | uint256(500_000));
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(2 gwei));

        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainOwnerKey, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        op.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        _artifactInit(LOG_FILE);
        vm.recordLogs();
        vm.broadcast(deployerKey);
        entryPoint.handleOps(ops, beneficiary);
        _logRecorded(LOG_FILE);

        require(
            mainAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""), "validator not installed"
        );
        require(mainAccount.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module), ""), "module not installed");
    }
}
