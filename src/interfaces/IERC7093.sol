// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Core data types for ERC-7093 recovery.
interface IERC7093 {
    /// @notice Guardian identity. Empty `signer` means an EOA / SCA account.
    struct Identity {
        address guardianVerifier;
        bytes signer;
    }

    /// @notice Guardian with a policy-defined `property` (e.g. weight).
    struct GuardianInfo {
        Identity guardian;
        uint64 property;
    }

    struct ThresholdConfig {
        uint64 threshold;
        int48 lockPeriod;
    }

    /// @notice Recovery configuration. `policyVerifier` is optional per EIP-7093.
    struct RecoveryConfigArg {
        address policyVerifier;
        GuardianInfo[] guardianInfos;
        ThresholdConfig[] thresholdConfigs;
    }

    struct Permission {
        Identity guardian;
        bytes signature;
    }
}
