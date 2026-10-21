// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {
    PackedUserOperation as AAPackedUserOperation
} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

import {IEntryPoint as OZEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    IERC7579Execution,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {Account as OZAccount} from "@openzeppelin/contracts/account/Account.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

import {SmartAccount} from "../src/SmartAccount.sol";
import {SimpleECDSAValidator} from "../src/validators/SimpleECDSAValidator.sol";
import {RecoveryModule} from "../src/RecoveryModule.sol";
import {SimpleThresholdPolicyVerifier} from "../src/verifiers/SimpleThresholdPolicyVerifier.sol";
import {IERC7093} from "../src/interfaces/IERC7093.sol";
import {MockTarget} from "./mocks/MockTarget.sol";
import {MockEntryPoint} from "./mocks/MockEntryPoint.sol";

/// @notice Tests for the modular SmartAccount (ERC-4337 + ERC-7579) and its
/// ERC-7093 recovery integration.
contract SmartAccountTest is Test {
    using UserOperationLib for AAPackedUserOperation;

    receive() external payable {}

    EntryPoint public entryPoint;
    SmartAccount public account;
    SimpleECDSAValidator public validator;
    RecoveryModule public module;
    SimpleThresholdPolicyVerifier public policyVerifier;
    MockTarget public target;

    MockEntryPoint public mockEntryPoint;
    SmartAccount public mockAccount;

    uint256 ownerKey;
    address owner;
    uint256 otherKey;
    address other;

    uint256 pkA = uint256(0x1111111111111111111111111111111111111111111111111111111111111111);
    uint256 pkB = uint256(0x2222222222222222222222222222222222222222222222222222222222222222);
    uint256 pkC = uint256(0x3333333333333333333333333333333333333333333333333333333333333333);
    address guardianA;
    address guardianB;
    address guardianC;

    uint256 constant LOCK = 1 hours;
    uint64 constant THRESHOLD = 2;
    address newOwner = address(0xaBcd000000000000000000000000000000000001);

    uint64 opSeq;

    function setUp() public {
        ownerKey = uint256(0x4444444444444444444444444444444444444444444444444444444444444444);
        owner = vm.addr(ownerKey);
        otherKey = uint256(0x5555555555555555555555555555555555555555555555555555555555555555);
        other = vm.addr(otherKey);
        guardianA = vm.addr(pkA);
        guardianB = vm.addr(pkB);
        guardianC = vm.addr(pkC);

        entryPoint = new EntryPoint();
        validator = new SimpleECDSAValidator();
        module = new RecoveryModule();
        target = new MockTarget();

        account = new SmartAccount(OZEntryPoint(address(entryPoint)), owner);
        vm.deal(address(account), 10 ether);
        vm.prank(owner);
        account.initializeAccount(address(validator), "");

        IERC7093.RecoveryConfigArg[] memory recoveryArgs = _configArgs();
        vm.prank(address(account));
        account.installModule(MODULE_TYPE_EXECUTOR, address(module), abi.encode(recoveryArgs));

        mockEntryPoint = new MockEntryPoint();
        mockAccount = new SmartAccount(OZEntryPoint(address(mockEntryPoint)), owner);
        vm.prank(owner);
        mockAccount.initializeAccount(address(validator), "");
    }

    function _guardianInfo(address g, uint64 w) internal pure returns (IERC7093.GuardianInfo memory) {
        return IERC7093.GuardianInfo(IERC7093.Identity(g, ""), w);
    }

    function _configArgs() internal returns (IERC7093.RecoveryConfigArg[] memory) {
        IERC7093.GuardianInfo[] memory g = new IERC7093.GuardianInfo[](3);
        g[0] = _guardianInfo(guardianA, 1);
        g[1] = _guardianInfo(guardianB, 1);
        g[2] = _guardianInfo(guardianC, 1);
        policyVerifier = new SimpleThresholdPolicyVerifier();
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](1);
        t[0] = IERC7093.ThresholdConfig(THRESHOLD, SafeCast.toInt48(SafeCast.toInt256(LOCK)));
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(policyVerifier), g, t);
        return args;
    }

    // Validator address occupies the top 20 bytes of the UserOp nonce.
    function _nextNonce() internal returns (uint256) {
        uint256 n = (uint256(uint160(address(validator))) << 96) | opSeq;
        opSeq += 1;
        return n;
    }

    function _encodeGasLimits(uint256 verification, uint256 callGas) internal pure returns (bytes32) {
        return bytes32((verification << 128) | (callGas & type(uint128).max));
    }

    function _encodeGasFees(uint256 maxPriority, uint256 maxFee) internal pure returns (bytes32) {
        return bytes32((maxPriority << 128) | (maxFee & type(uint128).max));
    }

    function _userOp(bytes memory callData, uint256 nonce) internal view returns (AAPackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = nonce;
        op.initCode = "";
        op.callData = callData;
        op.accountGasLimits = _encodeGasLimits(500_000, 500_000);
        op.preVerificationGas = 50_000;
        op.gasFees = _encodeGasFees(1 gwei, 2 gwei);
        op.paymasterAndData = "";
    }

    // Sign exactly as SimpleECDSAValidator expects: eth_signed_message(userOpHash).
    function _signOp(AAPackedUserOperation memory op, uint256 key)
        internal
        view
        returns (AAPackedUserOperation memory)
    {
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethHash);
        op.signature = abi.encodePacked(r, s, v);
        return op;
    }

    function _perms(bytes32 digest, uint256[] memory keys) internal pure returns (IERC7093.Permission[] memory) {
        IERC7093.Permission[] memory out = new IERC7093.Permission[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            out[i] = IERC7093.Permission(IERC7093.Identity(vm.addr(keys[i]), ""), abi.encodePacked(r, s, v));
        }
        return out;
    }

    function _guardianPerms(address acct, uint256 configIndex, address no, uint256[] memory keys)
        internal
        view
        returns (IERC7093.Permission[] memory)
    {
        return _perms(module.getRecoveryDigest(acct, configIndex, abi.encode(no)), keys);
    }

    function _arr(uint256 a, uint256 b) internal pure returns (uint256[] memory) {
        uint256[] memory x = new uint256[](2);
        x[0] = a;
        x[1] = b;
        return x;
    }

    function _arr(uint256 a) internal pure returns (uint256[] memory) {
        uint256[] memory x = new uint256[](1);
        x[0] = a;
        return x;
    }

    // ---------------------------------------------------------------------
    // Deployment / module lifecycle
    // ---------------------------------------------------------------------

    function test_OwnerInitialized() public view {
        assertEq(account.owner(), owner);
    }

    function test_EntryPointInitialized() public view {
        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function test_InvalidInitializationRejected() public {
        vm.expectRevert(SmartAccount.ZeroOwner.selector);
        new SmartAccount(OZEntryPoint(address(entryPoint)), address(0));

        vm.expectRevert(SmartAccount.ZeroEntryPoint.selector);
        new SmartAccount(OZEntryPoint(address(0)), owner);
    }

    function test_ValidatorInstalledAtInit() public view {
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""));
        assertTrue(account.supportsModule(MODULE_TYPE_VALIDATOR));
        assertTrue(account.supportsModule(MODULE_TYPE_EXECUTOR));
        assertFalse(account.supportsModule(MODULE_TYPE_HOOK));
        assertTrue(account.supportsModule(MODULE_TYPE_FALLBACK));
    }

    function test_RecoveryExecutorInstalledVia7579() public view {
        assertTrue(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module), ""));
        assertTrue(module.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(module.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(module.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(module.isModuleType(MODULE_TYPE_FALLBACK));
        assertTrue(module.installed(address(account)));
        assertEq(module.getRecoveryNonce(address(account)), 1);
        assertEq(module.getGuardians(address(account), 0).length, 3);
    }

    function test_OnInstallEmptyDataReverts() public {
        SmartAccount acc2 = new SmartAccount(OZEntryPoint(address(entryPoint)), owner);
        vm.prank(owner);
        acc2.initializeAccount(address(validator), "");
        vm.prank(address(acc2));
        vm.expectRevert("RecoveryModule: empty init");
        acc2.installModule(MODULE_TYPE_EXECUTOR, address(module), "");
    }

    function test_InitializeAccountOnlyOwner() public {
        SmartAccount acc = new SmartAccount(OZEntryPoint(address(entryPoint)), owner);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotOwner.selector, other));
        acc.initializeAccount(address(validator), "");

        vm.prank(owner);
        acc.initializeAccount(address(validator), "");
        assertTrue(acc.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""));
    }

    function test_UnauthorizedInstallReverts() public {
        IERC7093.RecoveryConfigArg[] memory args = _configArgs();
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(OZAccount.AccountUnauthorized.selector, other));
        account.installModule(MODULE_TYPE_EXECUTOR, address(module), abi.encode(args));
    }

    function test_UnauthorizedUninstallReverts() public {
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(OZAccount.AccountUnauthorized.selector, other));
        account.uninstallModule(MODULE_TYPE_EXECUTOR, address(module), "");
    }

    function test_InstallWrongTypeReverts() public {
        IERC7093.RecoveryConfigArg[] memory args = _configArgs();
        vm.prank(address(account));
        vm.expectRevert();
        account.installModule(MODULE_TYPE_VALIDATOR, address(module), abi.encode(args));
    }

    function test_UninstallBlocksRecovery() public {
        IERC7093.Permission[] memory p = _guardianPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);

        vm.prank(address(account));
        account.uninstallModule(MODULE_TYPE_EXECUTOR, address(module), "");

        assertFalse(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module), ""));
        assertFalse(module.installed(address(account)));

        vm.warp(block.timestamp + LOCK + 1);
        vm.expectRevert("RecoveryModule: not installed");
        module.executeRecovery(address(account), 0);

        IERC7093.Permission[] memory p2 = _guardianPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: not installed");
        module.startRecovery(address(account), 0, abi.encode(newOwner), p2);

        vm.prank(guardianA);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotAuthorizedRecovery.selector, guardianA));
        account.recoverOwner(abi.encode(newOwner));
    }

    // ---------------------------------------------------------------------
    // Normal authorization (validator) via EntryPoint
    // ---------------------------------------------------------------------

    function test_ValidatorUserOpExecutes() public {
        bytes memory exec =
            abi.encodePacked(address(target), uint256(0), abi.encodeWithSelector(MockTarget.setValue.selector, 777));
        bytes memory callData = abi.encodeCall(IERC7579Execution.execute, (bytes32(0), exec));
        AAPackedUserOperation memory op = _signOp(_userOp(callData, _nextNonce()), ownerKey);

        AAPackedUserOperation[] memory ops = new AAPackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(address(this)));
        assertEq(target.value(), 777);
    }

    function test_WrongKeyUserOpFails() public {
        bytes memory exec =
            abi.encodePacked(address(target), uint256(0), abi.encodeWithSelector(MockTarget.setValue.selector, 777));
        bytes memory callData = abi.encodeCall(IERC7579Execution.execute, (bytes32(0), exec));
        AAPackedUserOperation memory op = _signOp(_userOp(callData, _nextNonce()), otherKey);

        AAPackedUserOperation[] memory ops = new AAPackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert();
        entryPoint.handleOps(ops, payable(address(this)));
        assertEq(target.value(), 0);
    }

    function test_DirectExecuteUnauthorizedReverts() public {
        bytes memory exec =
            abi.encodePacked(address(target), uint256(0), abi.encodeWithSelector(MockTarget.setValue.selector, 1));
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(OZAccount.AccountUnauthorized.selector, other));
        account.execute(bytes32(0), exec);
    }

    function test_ValidOwnerSignatureAccepted() public {
        AAPackedUserOperation memory op = _userOp("", _nextNonce());
        bytes32 hash = mockEntryPoint.getUserOpHash(op);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ethHash);
        op.signature = abi.encodePacked(r, s, v);

        uint256 result = mockEntryPoint.callValidateUserOp(address(mockAccount), op, hash);
        assertEq(result, 0);
    }

    function test_InvalidSignatureRejected() public {
        AAPackedUserOperation memory op = _userOp("", _nextNonce());
        bytes32 hash = mockEntryPoint.getUserOpHash(op);
        op.signature = hex"deadbeef";

        uint256 result = mockEntryPoint.callValidateUserOp(address(mockAccount), op, hash);
        assertEq(result, 1);
    }

    function test_OtherAccountSignatureRejected() public {
        AAPackedUserOperation memory op = _userOp("", _nextNonce());
        bytes32 hash = mockEntryPoint.getUserOpHash(op);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherKey, ethHash);
        op.signature = abi.encodePacked(r, s, v);

        uint256 result = mockEntryPoint.callValidateUserOp(address(mockAccount), op, hash);
        assertEq(result, 1);
    }

    function test_ERC1271ViaValidator() public view {
        bytes32 hash = keccak256("hello-7579");
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ethHash);
        bytes memory sig = abi.encodePacked(address(validator), r, s, v);
        assertEq(account.isValidSignature(hash, sig), bytes4(0x1626ba7e));

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(otherKey, ethHash);
        bytes memory bad = abi.encodePacked(address(validator), r2, s2, v2);
        assertEq(account.isValidSignature(hash, bad), bytes4(0xffffffff));
    }

    // ---------------------------------------------------------------------
    // ERC-7093 recovery (executor path)
    // ---------------------------------------------------------------------

    function test_7579FullRecoveryCycle() public {
        uint256 fundsBefore = address(account).balance;
        IERC7093.Permission[] memory p = _guardianPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertEq(module.getRecoveryNonce(address(account)), 2);

        vm.warp(block.timestamp + LOCK + 1);
        module.executeRecovery(address(account), 0);

        assertEq(account.owner(), newOwner);
        assertEq(address(account).balance, fundsBefore);
    }

    function test_7579TimelockEnforced() public {
        IERC7093.Permission[] memory p = _guardianPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.expectRevert("RecoveryModule: time lock active");
        module.executeRecovery(address(account), 0);
    }

    function test_7579InsufficientGuardiansRejected() public {
        IERC7093.Permission[] memory p = _guardianPerms(address(account), 0, newOwner, _arr(pkA));
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
    }

    function test_7579DuplicateGuardianRejected() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = module.getRecoveryDigest(address(account), 0, no);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkA));
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_7579OwnerCanCancel() public {
        IERC7093.Permission[] memory p = _guardianPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.prank(owner);
        module.cancelRecovery(address(account), 0);
        assertFalse(module.getPendingRecovery(address(account), 0).active);
    }

    function test_7579ReplayAfterExecutionRejected() public {
        bytes memory no = abi.encode(newOwner);
        IERC7093.Permission[] memory p = _guardianPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, no, p);
        vm.warp(block.timestamp + LOCK + 1);
        module.executeRecovery(address(account), 0);
        assertEq(account.owner(), newOwner);

        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    // ---------------------------------------------------------------------
    // Cross-standard attacks
    // ---------------------------------------------------------------------

    function test_ConfigWithoutInstallDoesNotAuthorizeRecovery() public {
        SmartAccount acc2 = new SmartAccount(OZEntryPoint(address(entryPoint)), owner);
        vm.prank(owner);
        acc2.initializeAccount(address(validator), "");
        IERC7093.RecoveryConfigArg[] memory args = _configArgs();
        vm.prank(owner);
        module.updateGuardians(address(acc2), args);

        bytes memory no = abi.encode(newOwner);
        bytes32 d = module.getRecoveryDigest(address(acc2), 0, no);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkA, d);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(pkB, d);
        IERC7093.Permission[] memory p = new IERC7093.Permission[](2);
        p[0] = IERC7093.Permission(IERC7093.Identity(guardianA, ""), abi.encodePacked(r, s, v));
        p[1] = IERC7093.Permission(IERC7093.Identity(guardianB, ""), abi.encodePacked(rB, sB, vB));
        module.startRecovery(address(acc2), 0, no, p);

        vm.warp(block.timestamp + LOCK + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Utils.ERC7579UninstalledModule.selector, MODULE_TYPE_EXECUTOR, address(module)
            )
        );
        module.executeRecovery(address(acc2), 0);
        assertEq(acc2.owner(), owner);
    }

    function test_NormalOwnerCannotForceRotationWithoutGuardians() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(SmartAccount.NotAuthorizedRecovery.selector, owner));
        account.recoverOwner(abi.encode(other));
        assertEq(account.owner(), owner);
    }

    function test_StrangerCannotDriveRecovery() public {
        IERC7093.Permission[] memory empty = new IERC7093.Permission[](0);
        vm.prank(other);
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, abi.encode(newOwner), empty);

        vm.prank(other);
        vm.expectRevert("RecoveryModule: no active recovery");
        module.executeRecovery(address(account), 0);
    }
}
