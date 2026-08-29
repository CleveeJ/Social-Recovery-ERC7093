// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "./IERC7093.sol";

/// @notice ERC-7093 RecoveryPolicyVerifier abstraction (EIP-conformant shape).
/// @dev Decides whether submitted guardian Permissions satisfy the policy; the
///      RecoveryModule delegates all policy decisions here so policies are pluggable.
///      Signature: `verifyRecoveryPolicy(Permission[], uint64[]) → (bool succ, uint64 weight)`.
interface IRecoveryPolicyVerifier {
    /// @param permissions Guardian Permissions for this recovery (signatures already
    ///        verified by the RecoveryModule). This function checks membership + weight.
    /// @param properties Policy-defined per-guardian properties (e.g. weights); a concrete
    ///        verifier may ignore these and use its own stored guardian properties.
    /// @return succ   True iff the permissions satisfy the policy.
    /// @return weight The accumulated policy weight of the validated guardians.
    function verifyRecoveryPolicy(IERC7093.Permission[] calldata permissions, uint64[] calldata properties)
        external
        view
        returns (bool succ, uint64 weight);

    /// @dev Returns supported policy settings and accompanying property definitions.
    function getPolicyVerifierInfo() external pure returns (bytes memory);
}
