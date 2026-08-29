// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {SmartAccount} from "../src/SmartAccount.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {RecoveryModule} from "../src/RecoveryModule.sol";
import {SimpleGuardianVerifier} from "../src/verifiers/SimpleGuardianVerifier.sol";
import {SimpleThresholdPolicyVerifier} from "../src/verifiers/SimpleThresholdPolicyVerifier.sol";

import {IERC7093} from "../src/interfaces/IERC7093.sol";
import {MockERC1271Guardian} from "./mocks/MockERC1271Guardian.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Foundry tests for the ERC-7093 RecoveryModule (MULTI-TENANT module design).
contract RecoveryModuleTest is Test {
    EntryPoint public entryPoint;
    SmartAccount public account;
    RecoveryModule public module;
    SimpleGuardianVerifier public guardianVerifier;
    SimpleThresholdPolicyVerifier public policyVerifier;

    uint256 ownerKey;
    address owner;

    // Guardian keys (EOA).
    uint256 pkA = uint256(0x1111111111111111111111111111111111111111111111111111111111111111);
    uint256 pkB = uint256(0x2222222222222222222222222222222222222222222222222222222222222222);
    uint256 pkC = uint256(0x3333333333333333333333333333333333333333333333333333333333333333);
    uint256 pkStranger = uint256(0x9999999999999999999999999999999999999999999999999999999999999999);
    address guardianA = vm.addr(pkA);
    address guardianB = vm.addr(pkB);
    address guardianC = vm.addr(pkC);
    address stranger = vm.addr(pkStranger);

    uint256 constant LOCK = 1 hours;
    uint64 constant THRESHOLD = 2;
    address newOwner = address(0xaBcd000000000000000000000000000000000001);

    function setUp() public {
        ownerKey = uint256(0x4444444444444444444444444444444444444444444444444444444444444444);
        owner = vm.addr(ownerKey);

        entryPoint = new EntryPoint();
        account = new SmartAccount(IEntryPoint(address(entryPoint)), owner);
        guardianVerifier = new SimpleGuardianVerifier();
        module = new RecoveryModule();

        // Authorize the module on the account.
        vm.prank(owner);
        account.setRecoveryModule(address(module));

        _configureConfig0();
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    function _guardianInfo(address g, uint64 w) internal pure returns (IERC7093.GuardianInfo memory) {
        return IERC7093.GuardianInfo(IERC7093.Identity(g, ""), w);
    }

    function _g3() internal view returns (IERC7093.GuardianInfo[] memory) {
        IERC7093.GuardianInfo[] memory g = new IERC7093.GuardianInfo[](3);
        g[0] = _guardianInfo(guardianA, 1);
        g[1] = _guardianInfo(guardianB, 1);
        g[2] = _guardianInfo(guardianC, 1);
        return g;
    }

    /// @dev Deploy a SimpleThresholdPolicyVerifier seeded with `g` and register it
    ///      as the sole recovery config for `account`.
    function _configureConfig0() internal {
        IERC7093.GuardianInfo[] memory g = _g3();
        policyVerifier = new SimpleThresholdPolicyVerifier(g);
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](1);
        t[0] = IERC7093.ThresholdConfig(THRESHOLD, SafeCast.toInt48(SafeCast.toInt256(LOCK)));
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(policyVerifier), g, t);
        vm.prank(owner);
        module.updateGuardians(address(account), args);
    }

    /// @dev Mirror of the module's EIP-712 digest so tests can craft a tampered
    ///      digest (wrong chainId / nonce / account / newOwner) and prove rejection.
    function _digest(uint256 chainId, uint256 configIndex, address acct, bytes memory newOwnerBytes, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32 DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 domain = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ERC7093Recovery"), keccak256("1"), chainId, address(module)));
        bytes32 TYPEHASH = keccak256("StartRecovery(uint256 configIndex,address account,bytes newOwners,uint256 nonce)");
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, configIndex, acct, keccak256(newOwnerBytes), nonce));
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _perms(bytes32 digest, uint256[] memory keys) internal pure returns (IERC7093.Permission[] memory) {
        IERC7093.Permission[] memory out = new IERC7093.Permission[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            out[i] = IERC7093.Permission(IERC7093.Identity(vm.addr(keys[i]), ""), sig);
        }
        return out;
    }

    /// @dev Guardian permissions signing the CURRENT recovery digest (start path).
    function _permsValid(address acct, uint256 configIndex, address no, uint256[] memory keys)
        internal
        view
        returns (IERC7093.Permission[] memory)
    {
        bytes memory noBytes = abi.encode(no);
        bytes32 digest = module.getRecoveryDigest(acct, configIndex, noBytes);
        return _perms(digest, keys);
    }

    /// @dev Guardian permissions signing the PENDING recovery's digest (cancel path).
    function _cancelPerms(address acct, uint256 configIndex, address no, uint256[] memory keys)
        internal
        view
        returns (IERC7093.Permission[] memory)
    {
        bytes memory noBytes = abi.encode(no);
        uint256 nonce = module.getPendingRecovery(acct, configIndex).nonce;
        bytes32 digest = _digest(block.chainid, configIndex, acct, noBytes, nonce);
        return _perms(digest, keys);
    }

    function _garbageSig() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
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

    function _arr(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory) {
        uint256[] memory x = new uint256[](3);
        x[0] = a;
        x[1] = b;
        x[2] = c;
        return x;
    }

    function _arr(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256[] memory) {
        uint256[] memory x = new uint256[](4);
        x[0] = a;
        x[1] = b;
        x[2] = c;
        x[3] = d;
        return x;
    }

    // ---------------------------------------------------------------------
    // Configuration (EIP-7093 updateGuardians)
    // ---------------------------------------------------------------------

    function test_OwnerCanConfigureGuardians() public view {
        IERC7093.GuardianInfo[] memory g = module.getGuardians(address(account), 0);
        assertEq(g.length, 3);
        assertEq(g[0].guardian.guardianVerifier, guardianA);
        assertEq(g[1].guardian.guardianVerifier, guardianB);
        assertEq(g[2].guardian.guardianVerifier, guardianC);
    }

    function test_ThresholdStored() public view {
        assertEq(module.getThresholdConfigs(address(account), 0)[0].threshold, THRESHOLD);
    }

    function test_LockPeriodStored() public view {
        assertEq(module.getThresholdConfigs(address(account), 0)[0].lockPeriod, SafeCast.toInt48(SafeCast.toInt256(LOCK)));
    }

    function test_PolicyVerifierStored() public view {
        assertEq(module.getPolicyVerifier(address(account), 0), address(policyVerifier));
    }

    function test_UnauthorizedCannotModifyGuardians() public {
        IERC7093.GuardianInfo[] memory g = new IERC7093.GuardianInfo[](1);
        g[0] = _guardianInfo(guardianA, 1);
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](1);
        t[0] = IERC7093.ThresholdConfig(1, 0);
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(policyVerifier), g, t);

        vm.prank(stranger);
        vm.expectRevert("RecoveryModule: not owner");
        module.updateGuardians(address(account), args);
    }

    function test_GetRecoveryConfigs() public view {
        IERC7093.RecoveryConfigArg[] memory cfgs = module.getRecoveryConfigs(address(account));
        assertEq(cfgs.length, 1);
        assertEq(cfgs[0].policyVerifier, address(policyVerifier));
        assertEq(cfgs[0].guardianInfos.length, 3);
    }

    function test_DomainSeparators() public view {
        assertEq(module.DOMAIN_SEPARATOR_NAME(), "ERC7093Recovery");
        assertEq(module.DOMAIN_SEPARATOR_VERSION(), "1");
        assertEq(module.domainSeparatorV4(), _domainSeparatorV4());
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        bytes32 DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("ERC7093Recovery"), keccak256("1"), block.chainid, address(module))
        );
    }

    // ---------------------------------------------------------------------
    // Guardian verification / threshold (2-of-3)
    // ---------------------------------------------------------------------

    function test_ThresholdAB() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertTrue(module.getPendingRecovery(address(account), 0).active);
    }

    function test_ThresholdAC() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkC));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertTrue(module.getPendingRecovery(address(account), 0).active);
    }

    function test_ThresholdBC() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkB, pkC));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertTrue(module.getPendingRecovery(address(account), 0).active);
    }

    function test_FailsAlone_A() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA));
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
    }

    function test_InvalidPlusValidFails() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = module.getRecoveryDigest(address(account), 0, no);
        IERC7093.Permission[] memory p = new IERC7093.Permission[](2);
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(pkA, digest);
        p[0] = IERC7093.Permission(IERC7093.Identity(guardianA, ""), abi.encodePacked(rA, sA, vA));
        p[1] = IERC7093.Permission(IERC7093.Identity(guardianB, ""), _garbageSig());
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_NonGuardianSignatureRejected() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = module.getRecoveryDigest(address(account), 0, no);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkStranger, pkA));
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_DuplicateGuardianRejected() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = module.getRecoveryDigest(address(account), 0, no);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkA));
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_TooManyPermissionsRejected() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = module.getRecoveryDigest(address(account), 0, no);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkB, pkC, pkA));
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, no, p);
    }

    // ---------------------------------------------------------------------
    // Recovery lifecycle
    // ---------------------------------------------------------------------

    function test_RecoveryStartedEmitted() public {
        bytes memory no = abi.encode(newOwner);
        uint48 expected = SafeCast.toUint48(block.timestamp) + SafeCast.toUint48(LOCK);
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));

        vm.expectEmit(false, false, false, true, address(module));
        emit RecoveryModule.RecoveryStarted(no, 0, expected);
        module.startRecovery(address(account), 0, no, p);
    }

    function test_PendingRecoveryStored() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        RecoveryModule.PendingRecovery memory pr = module.getPendingRecovery(address(account), 0);
        assertEq(abi.decode(pr.newOwner, (address)), newOwner);
        assertEq(pr.nonce, 0);
        assertEq(pr.executeAfter, SafeCast.toUint48(block.timestamp) + SafeCast.toUint48(LOCK));
        assertTrue(pr.active);
    }

    function test_RecoveryStatusActive() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        (bool active, uint48 exp) = module.getRecoveryStatus(address(account), 0);
        assertTrue(active);
        assertEq(exp, SafeCast.toUint48(block.timestamp) + SafeCast.toUint48(LOCK));
    }

    function test_ExecuteBeforeLockFails() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.expectRevert("RecoveryModule: time lock active");
        module.executeRecovery(address(account), 0);
    }

    function test_ExecuteAfterLockSucceeds() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.warp(block.timestamp + LOCK + 1);
        vm.expectEmit(false, false, false, true, address(module));
        emit RecoveryModule.RecoveryExecuted(abi.encode(newOwner), 0);
        module.executeRecovery(address(account), 0);
        assertEq(account.owner(), newOwner);
    }

    function test_OwnerChangesAfterRecovery() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.warp(block.timestamp + LOCK + 1);
        module.executeRecovery(address(account), 0);
        assertEq(account.owner(), newOwner);
    }

    function test_UnauthorizedCannotDirectlyChangeOwner() public {
        vm.prank(stranger);
        vm.expectRevert("SmartAccount: not recovery module");
        account.recoverOwner(abi.encode(newOwner));
    }

    // ---------------------------------------------------------------------
    // Replay protection (separate recovery nonce, per account)
    // ---------------------------------------------------------------------

    function test_RecoveryNonceIncrements() public {
        assertEq(module.getRecoveryNonce(address(account)), 0);
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertEq(module.getRecoveryNonce(address(account)), 1);
    }

    function test_ReplaySamePermissionsRejected() public {
        bytes memory no = abi.encode(newOwner);
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, no, p);
        vm.warp(block.timestamp + LOCK + 1);
        module.executeRecovery(address(account), 0);
        assertEq(account.owner(), newOwner);

        // Same signatures (bound to nonce 0); module now computes digest with nonce 1.
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_SignatureForAnotherNonceRejected() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = _digest(block.chainid, 0, address(account), no, 12345);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_SignatureForAnotherChainRejected() public {
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = _digest(99999, 0, address(account), no, 0);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    function test_SignatureForAnotherNewOwnerRejected() public {
        bytes memory no = abi.encode(newOwner);
        address other = address(0x1234);
        bytes32 digest = _digest(block.chainid, 0, address(account), abi.encode(other), 0);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    /// @dev The EIP-712 digest now binds `account` AND `verifyingContract` (this shared
    ///      module). A signature produced for a DIFFERENT account does not validate.
    function test_SignatureForAnotherAccountRejected() public {
        // Configure an identical guardian set for a second account on the SAME module.
        SmartAccount acc2 = new SmartAccount(IEntryPoint(address(entryPoint)), owner);
        vm.prank(owner);
        acc2.setRecoveryModule(address(module));
        IERC7093.GuardianInfo[] memory g = _g3();
        SimpleThresholdPolicyVerifier v2 = new SimpleThresholdPolicyVerifier(g);
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](1);
        t[0] = IERC7093.ThresholdConfig(THRESHOLD, 0);
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(v2), g, t);
        vm.prank(owner);
        module.updateGuardians(address(acc2), args);

        // Guardians A,B sign over ACCOUNT 2's digest, then submit to ACCOUNT 1.
        bytes memory no = abi.encode(newOwner);
        bytes32 digest2 = module.getRecoveryDigest(address(acc2), 0, no);
        IERC7093.Permission[] memory p = _perms(digest2, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    /// @dev Account binding is also enforced via the EIP-712 `verifyingContract`
    ///      (this shared module). A signature produced for a DIFFERENT module does
    ///      not validate on this one.
    function test_SignatureForAnotherModuleRejected() public {
        SmartAccount acc2 = new SmartAccount(IEntryPoint(address(entryPoint)), owner);
        RecoveryModule mod2 = new RecoveryModule();
        vm.prank(owner);
        acc2.setRecoveryModule(address(mod2));
        IERC7093.GuardianInfo[] memory g = _g3();
        SimpleThresholdPolicyVerifier v2 = new SimpleThresholdPolicyVerifier(g);
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](1);
        t[0] = IERC7093.ThresholdConfig(THRESHOLD, 0);
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(v2), g, t);
        vm.prank(owner);
        mod2.updateGuardians(address(acc2), args);

        // Guardians A,B sign over MODULE 2's digest, then submit to MODULE 1.
        bytes memory no = abi.encode(newOwner);
        bytes32 digest2 = mod2.getRecoveryDigest(address(acc2), 0, no);
        IERC7093.Permission[] memory p = _perms(digest2, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: bad guardian signature");
        module.startRecovery(address(account), 0, no, p);
    }

    // ---------------------------------------------------------------------
    // Per-account isolation
    // ---------------------------------------------------------------------

    function test_AccountsAreIsolated() public {
        // A fresh account that never registered a config cannot start a recovery.
        SmartAccount accB = new SmartAccount(IEntryPoint(address(entryPoint)), owner);
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: invalid configIndex");
        module.startRecovery(address(accB), 0, abi.encode(newOwner), p);
    }

    function test_CancelByStrangerOnOtherAccountReverts() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);

        // A recovery active on `account` must NOT bleed into another account.
        SmartAccount accB = new SmartAccount(IEntryPoint(address(entryPoint)), owner);
        vm.prank(owner);
        vm.expectRevert("RecoveryModule: no active recovery");
        module.cancelRecovery(address(accB), 0);
    }

    function test_ZeroAccountRejected() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: zero account");
        module.startRecovery(address(0), 0, abi.encode(newOwner), p);
    }

    // ---------------------------------------------------------------------
    // Cancellation
    // ---------------------------------------------------------------------

    function test_CancelByOwnerRemovesPending() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.expectEmit(false, false, false, true, address(module));
        emit RecoveryModule.RecoveryCanceled(0);
        vm.prank(owner);
        module.cancelRecovery(address(account), 0);
        assertFalse(module.getPendingRecovery(address(account), 0).active);
    }

    function test_CancelByNonOwnerReverts() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.prank(stranger);
        vm.expectRevert("RecoveryModule: not owner");
        module.cancelRecovery(address(account), 0);
    }

    function test_CancelByGuardians() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        IERC7093.Permission[] memory cp = _cancelPerms(address(account), 0, newOwner, _arr(pkA, pkB));
        vm.expectEmit(false, false, false, true, address(module));
        emit RecoveryModule.RecoveryCanceled(0);
        module.cancelRecoveryByGuardians(address(account), 0, cp);
        assertFalse(module.getPendingRecovery(address(account), 0).active);
    }

    function test_CancelByGuardiansBelowQuorumFails() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        // Only guardian A cancels (weight 1 < threshold 2).
        IERC7093.Permission[] memory cp = _cancelPerms(address(account), 0, newOwner, _arr(pkA));
        vm.expectRevert("RecoveryModule: quorum not met");
        module.cancelRecoveryByGuardians(address(account), 0, cp);
        assertTrue(module.getPendingRecovery(address(account), 0).active);
    }

    function test_RecoveryCannotExecuteTwice() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.warp(block.timestamp + LOCK + 1);
        module.executeRecovery(address(account), 0);
        vm.expectRevert("RecoveryModule: no active recovery");
        module.executeRecovery(address(account), 0);
    }

    function test_RecoveryCannotCancelAfterExecution() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        vm.warp(block.timestamp + LOCK + 1);
        module.executeRecovery(address(account), 0);
        vm.prank(newOwner);
        vm.expectRevert("RecoveryModule: no active recovery");
        module.cancelRecovery(address(account), 0);
    }

    // ---------------------------------------------------------------------
    // Multi-tier threshold selection
    // ---------------------------------------------------------------------

    function _configureMultiTier() internal {
        IERC7093.GuardianInfo[] memory g = _g3();
        SimpleThresholdPolicyVerifier v = new SimpleThresholdPolicyVerifier(g);
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](2);
        t[0] = IERC7093.ThresholdConfig(2, SafeCast.toInt48(SafeCast.toInt256(LOCK))); // 2-of-3 → 1h lock
        t[1] = IERC7093.ThresholdConfig(3, 0); // 3-of-3 → instant
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(v), g, t);
        vm.prank(owner);
        module.updateGuardians(address(account), args);
    }

    function test_MultiTier_TwoGuardiansGetsLock() public {
        _configureMultiTier();
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertEq(module.getPendingRecovery(address(account), 0).executeAfter, SafeCast.toUint48(block.timestamp) + SafeCast.toUint48(LOCK));
    }

    function test_MultiTier_ThreeGuardiansInstant() public {
        _configureMultiTier();
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB, pkC));
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
        assertEq(module.getPendingRecovery(address(account), 0).executeAfter, uint48(block.timestamp));
        module.executeRecovery(address(account), 0);
        assertEq(account.owner(), newOwner);
    }

    // ---------------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------------

    function test_ZeroAddressNewOwnerRejected() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, address(0), _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: zero newOwner");
        module.startRecovery(address(account), 0, abi.encode(address(0)), p);
    }

    function test_InvalidConfigIndexRejected() public {
        IERC7093.Permission[] memory p = _permsValid(address(account), 0, newOwner, _arr(pkA, pkB));
        vm.expectRevert("RecoveryModule: invalid configIndex");
        module.startRecovery(address(account), 99, abi.encode(newOwner), p);
    }

    function test_EmptyPermissionsRejected() public {
        IERC7093.Permission[] memory p = new IERC7093.Permission[](0);
        vm.expectRevert("RecoveryModule: verification failed");
        module.startRecovery(address(account), 0, abi.encode(newOwner), p);
    }

    // ---------------------------------------------------------------------
    // ERC-1271 guardian compatibility
    // ---------------------------------------------------------------------

    function test_ERC1271GuardianAccepted() public {
        // Config 0: A, B (EOA) + G (smart-contract guardian, validated by key C).
        MockERC1271Guardian g = new MockERC1271Guardian(guardianC);
        IERC7093.GuardianInfo[] memory gi = new IERC7093.GuardianInfo[](3);
        gi[0] = _guardianInfo(guardianA, 1);
        gi[1] = _guardianInfo(guardianB, 1);
        gi[2] = _guardianInfo(address(g), 1);
        SimpleThresholdPolicyVerifier v = new SimpleThresholdPolicyVerifier(gi);
        IERC7093.ThresholdConfig[] memory t = new IERC7093.ThresholdConfig[](1);
        t[0] = IERC7093.ThresholdConfig(THRESHOLD, 0); // no lock, simpler
        IERC7093.RecoveryConfigArg[] memory args = new IERC7093.RecoveryConfigArg[](1);
        args[0] = IERC7093.RecoveryConfigArg(address(v), gi, t);
        vm.prank(owner);
        module.updateGuardians(address(account), args);

        // A (EOA) + G (contract, validated by key C). Retarget C's Identity to the
        // contract guardian; the module verifies G via ERC-1271 (SignatureChecker).
        bytes memory no = abi.encode(newOwner);
        bytes32 digest = module.getRecoveryDigest(address(account), 0, no);
        IERC7093.Permission[] memory p = _perms(digest, _arr(pkA, pkC));
        p[1].guardian = IERC7093.Identity(address(g), "");

        module.startRecovery(address(account), 0, no, p);
        assertTrue(module.getPendingRecovery(address(account), 0).active);
    }

    // ---------------------------------------------------------------------
    // SimpleGuardianVerifier (EIP-7093 IPermissionVerifier) unit tests
    // ---------------------------------------------------------------------

    function test_GuardianVerifier_EOA() public view {
        bytes32 hash = keccak256("recovery");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkA, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        assertTrue(guardianVerifier.isValidPermission(hash, abi.encode(guardianA), sig));
        assertFalse(guardianVerifier.isValidPermission(hash, abi.encode(guardianB), sig));
    }

    function test_GuardianVerifier_SCA() public {
        MockERC1271Guardian g = new MockERC1271Guardian(guardianC);
        bytes32 hash = keccak256("recovery");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkC, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        assertTrue(guardianVerifier.isValidPermission(hash, abi.encode(address(g)), sig));
    }

    function test_GuardianVerifier_Validators() public view {
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encode(guardianA);
        assertTrue(guardianVerifier.isValidSigners(signers));
        signers[0] = bytes("bad");
        assertFalse(guardianVerifier.isValidSigners(signers));
        assertTrue(guardianVerifier.getGuardianVerifierInfo().length > 0);
    }
}
