// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice ERC-7093 core data types.
/// @dev These mirror the draft EIP-7093 structs. The thesis uses a concrete
///      EOA-based 2-of-3 threshold recovery policy, but the data structures
///      themselves follow the EIP so the account stays ERC-7093-aligned.
interface IERC7093 {
    /// @notice Identifies a Guardian (or, more generally, a signer).
    /// @dev For an EOA Guardian, `guardianVerifier` IS the signer address and
    ///      `signer` MUST be empty (per EIP-7093). For a smart-contract Guardian
    ///      `guardianVerifier` is the verifying contract and `signer` may carry an
    ///      application-specific sub-identity. This thesis only implements the EOA
    ///      case; the field is kept so the architecture is ERC-1271-ready.
    struct Identity {
        address guardianVerifier;
        bytes signer;
    }

    /// @notice A Guardian together with its policy-specific `property`.
    /// @dev In ERC-7093 the `property` is intentionally policy-defined rather than
    ///      hard-coded. For the thesis's weighted threshold it is the Guardian's
    ///      weight (each of the 3 Guardians has weight 1, threshold = 2).
    struct GuardianInfo {
        Identity guardian;
        uint64 property;
    }

    /// @notice Threshold and time-lock for a recovery configuration.
    /// @dev ERC-7093 associates the threshold with a `lockPeriod`. The lock period
    ///      is intentionally NOT hard-coded; it is configured per recovery config.
    struct ThresholdConfig {
        uint64 threshold;
        int48 lockPeriod;
    }

    /// @notice A full recovery configuration argument (EIP-7093 style).
    /// @dev `policyVerifier` is the RecoveryPolicyVerifier contract that validates a
    ///      set of guardian Permissions against this config. It is optional per the
    ///      EIP; the thesis supplies a concrete SimpleThresholdPolicyVerifier.
    struct RecoveryConfigArg {
        address policyVerifier;
        GuardianInfo[] guardianInfos;
        ThresholdConfig[] thresholdConfigs;
    }

    /// @notice A single Guardian's authorization: its Identity plus the signature
    ///         (proof) over the EIP-712 recovery message.
    struct Permission {
        Identity guardian;
        bytes signature;
    }
}
