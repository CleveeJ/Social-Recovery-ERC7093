// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Test mock of a smart-contract (ERC-1271) Guardian.
/// Validates by ECDSA-recovering against a stored key, then returns the magic value.
contract MockERC1271Guardian is IERC1271 {
    address public ownerKey;

    constructor(address _ownerKey) {
        ownerKey = _ownerKey;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == ownerKey) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }
}
