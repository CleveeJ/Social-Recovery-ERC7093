// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/UserOperationLib.sol";

/// @notice ISOLATED TEST MOCK. This is NOT a real ERC-4337 EntryPoint.
///         It exists only to unit-test SmartAccount.validateUserOp()'s
///         signature logic while satisfying BaseAccount's requirement that
///         msg.sender == entryPoint. All real end-to-end tests use the canonical
///         EntryPoint from lib/account-abstraction instead.
contract MockEntryPoint {
    using UserOperationLib for PackedUserOperation;

    /// @dev Mirrors IEntryPoint.getUserOpHash so signatures produced in tests
    ///      match what the account expects.
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    /// @dev Calls the account's validateUserOp as if it were the EntryPoint.
    function callValidateUserOp(address account, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256 validationData)
    {
        (bool success, bytes memory ret) = account.call(
            abi.encodeWithSignature(
                "validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32,uint256)",
                userOp,
                userOpHash,
                uint256(0)
            )
        );
        if (!success) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        validationData = abi.decode(ret, (uint256));
    }
}
