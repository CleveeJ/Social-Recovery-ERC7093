// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/UserOperationLib.sol";

/// @notice Test-only EntryPoint mock for isolated `validateUserOp` unit tests.
contract MockEntryPoint {
    using UserOperationLib for PackedUserOperation;

    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

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
