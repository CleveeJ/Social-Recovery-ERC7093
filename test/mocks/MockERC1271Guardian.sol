// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC1271} from "../../src/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Test mock of a smart-contract (ERC-1271) Guardian.
/// @dev It validates a signature by ECDSA-recovering it against a stored key, then
///      returns the ERC-1271 magic value. This lets the test exercise the
///      `SCA → ERC-1271` branch of SimpleGuardianVerifier without a full wallet.
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
