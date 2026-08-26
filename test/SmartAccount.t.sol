// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {SmartAccount} from "../src/SmartAccount.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {MockTarget} from "./mocks/MockTarget.sol";
import {MockEntryPoint} from "./mocks/MockEntryPoint.sol";

/// @notice Foundry tests for the minimal ERC-4337 SmartAccount foundation.
contract SmartAccountTest is Test {
    using UserOperationLib for PackedUserOperation;

    // Accept ETH so the EntryPoint can pay this contract as the handleOps
    // beneficiary (gas fees).
    receive() external payable {}

    EntryPoint public realEntryPoint;
    SmartAccount public account; // deployed against the real EntryPoint

    MockEntryPoint public mockEntryPoint;
    SmartAccount public mockAccount; // deployed against the mock EntryPoint

    MockTarget public target;

    uint256 ownerKey;
    address owner;
    uint256 otherKey;
    address other;

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    function setUp() public {
        ownerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        owner = vm.addr(ownerKey);
        otherKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        other = vm.addr(otherKey);

        realEntryPoint = new EntryPoint();
        account = new SmartAccount(realEntryPoint, owner);

        mockEntryPoint = new MockEntryPoint();
        mockAccount = new SmartAccount(IEntryPoint(address(mockEntryPoint)), owner);

        target = new MockTarget();

        // Fund the real account with ETH so it can pay its own prefund when
        // executing UserOperations without a paymaster.
        vm.deal(address(account), 10 ether);
    }

    function _encodeGasLimits(uint256 verification, uint256 callGas) internal pure returns (bytes32) {
        return bytes32((verification << 128) | (callGas & type(uint128).max));
    }

    function _encodeGasFees(uint256 maxPriority, uint256 maxFee) internal pure returns (bytes32) {
        return bytes32((maxPriority << 128) | (maxFee & type(uint128).max));
    }

    function _buildOp(address sender, bytes memory callData, uint256 nonce)
        internal
        pure
        returns (PackedUserOperation memory op)
    {
        op.sender = sender;
        op.nonce = nonce;
        op.initCode = "";
        op.callData = callData;
        op.accountGasLimits = _encodeGasLimits(500_000, 500_000);
        op.preVerificationGas = 50_000;
        op.gasFees = _encodeGasFees(1 gwei, 2 gwei);
        op.paymasterAndData = "";
    }

    /// @dev Sign the ERC-4337 userOpHash exactly as the SmartAccount expects:
    ///      eth_signed_message(userOpHash) verified with OZ ECDSA.
    function _signOp(IEntryPoint ep, PackedUserOperation memory op, uint256 key)
        internal
        view
        returns (PackedUserOperation memory)
    {
        bytes32 userOpHash = ep.getUserOpHash(op);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethHash);
        op.signature = abi.encodePacked(r, s, v);
        return op;
    }

    // ---------------------------------------------------------------------
    // Deployment
    // ---------------------------------------------------------------------

    function test_OwnerInitialized() public view {
        assertEq(account.owner(), owner);
    }

    function test_EntryPointInitialized() public view {
        assertEq(address(account.entryPoint()), address(realEntryPoint));
    }

    function test_InvalidInitializationRejected() public {
        vm.expectRevert("SmartAccount: zero owner");
        new SmartAccount(realEntryPoint, address(0));

        vm.expectRevert("SmartAccount: zero entryPoint");
        new SmartAccount(IEntryPoint(address(0)), owner);
    }

    // ---------------------------------------------------------------------
    // Direct execution
    // ---------------------------------------------------------------------

    function test_OwnerCanExecute() public {
        vm.prank(owner);
        account.execute(address(target), 0, abi.encodeWithSelector(MockTarget.setValue.selector, 42));
        assertEq(target.value(), 42);
    }

    function test_UnauthorizedCannotExecute() public {
        vm.prank(other);
        vm.expectRevert("SmartAccount: not authorized");
        account.execute(address(target), 0, abi.encodeWithSelector(MockTarget.setValue.selector, 42));
        assertEq(target.value(), 0);
    }

    function test_EthValueTransfer() public {
        uint256 before = address(target).balance;
        vm.prank(owner);
        account.execute(address(target), 1 ether, "");
        assertEq(address(target).balance - before, 1 ether);
    }

    function test_CallDataForwarded() public {
        vm.prank(owner);
        account.execute(address(target), 0, abi.encodeWithSelector(MockTarget.setValue.selector, 123));
        assertEq(target.value(), 123);
    }

    function test_FailedTargetCallReverts() public {
        vm.prank(owner);
        vm.expectRevert("MockTarget: intentional failure");
        account.execute(address(target), 0, abi.encodeWithSelector(MockTarget.fail.selector));
    }

    // ---------------------------------------------------------------------
    // UserOperation validation (signature logic, isolated via MockEntryPoint)
    // ---------------------------------------------------------------------

    function test_ValidOwnerSignatureAccepted() public {
        PackedUserOperation memory op = _buildOp(
            address(mockAccount),
            abi.encodeWithSelector(
                SmartAccount.execute.selector,
                address(target),
                0,
                abi.encodeWithSelector(MockTarget.setValue.selector, 1)
            ),
            0
        );
        bytes32 hash = mockEntryPoint.getUserOpHash(op);
        op = _signOp(IEntryPoint(address(mockEntryPoint)), op, ownerKey);

        uint256 result = mockEntryPoint.callValidateUserOp(address(mockAccount), op, hash);
        assertEq(result, 0); // SIG_VALIDATION_SUCCESS
    }

    function test_InvalidSignatureRejected() public {
        PackedUserOperation memory op = _buildOp(
            address(mockAccount),
            abi.encodeWithSelector(
                SmartAccount.execute.selector,
                address(target),
                0,
                abi.encodeWithSelector(MockTarget.setValue.selector, 1)
            ),
            0
        );
        bytes32 hash = mockEntryPoint.getUserOpHash(op);
        // Garbage signature.
        op.signature = hex"deadbeef";

        uint256 result = mockEntryPoint.callValidateUserOp(address(mockAccount), op, hash);
        assertEq(result, 1); // SIG_VALIDATION_FAILED
    }

    function test_OtherAccountSignatureRejected() public {
        PackedUserOperation memory op = _buildOp(
            address(mockAccount),
            abi.encodeWithSelector(
                SmartAccount.execute.selector,
                address(target),
                0,
                abi.encodeWithSelector(MockTarget.setValue.selector, 1)
            ),
            0
        );
        bytes32 hash = mockEntryPoint.getUserOpHash(op);
        // Signed by a different key than the owner.
        op = _signOp(IEntryPoint(address(mockEntryPoint)), op, otherKey);

        uint256 result = mockEntryPoint.callValidateUserOp(address(mockAccount), op, hash);
        assertEq(result, 1); // SIG_VALIDATION_FAILED
    }

    function test_UnauthorizedCallerCannotInvokeEntryPointOnly() public {
        PackedUserOperation memory op = _buildOp(address(mockAccount), "", 0);
        bytes32 hash = mockEntryPoint.getUserOpHash(op);

        // Call validateUserOp directly (msg.sender == test contract, not EntryPoint).
        vm.expectRevert("SmartAccount: not from EntryPoint");
        mockAccount.validateUserOp(op, hash, 0);
    }

    // ---------------------------------------------------------------------
    // UserOperation execution (end-to-end via the real EntryPoint)
    // ---------------------------------------------------------------------

    function test_ValidUserOpExecutes() public {
        PackedUserOperation memory op = _buildOp(
            address(account),
            abi.encodeWithSelector(
                SmartAccount.execute.selector,
                address(target),
                0,
                abi.encodeWithSelector(MockTarget.setValue.selector, 777)
            ),
            0
        );
        op = _signOp(realEntryPoint, op, ownerKey);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        realEntryPoint.handleOps(ops, payable(address(this)));
        assertEq(target.value(), 777);
    }

    function test_InvalidUserOpDoesNotExecute() public {
        PackedUserOperation memory op = _buildOp(
            address(account),
            abi.encodeWithSelector(
                SmartAccount.execute.selector,
                address(target),
                0,
                abi.encodeWithSelector(MockTarget.setValue.selector, 777)
            ),
            0
        );
        // Signed by the wrong key → validation fails.
        op = _signOp(realEntryPoint, op, otherKey);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert();
        realEntryPoint.handleOps(ops, payable(address(this)));
        assertEq(target.value(), 0);
    }
}
