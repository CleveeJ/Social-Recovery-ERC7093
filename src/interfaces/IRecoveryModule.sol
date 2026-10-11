// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7093} from "./IERC7093.sol";

interface IRecoveryModule {
    event RecoveryStarted(bytes newOwners, uint256 nonce, uint48 expiryTime);
    event RecoveryExecuted(bytes newOwners, uint256 nonce);
    event RecoveryCanceled(uint256 nonce);

    function updateGuardians(address account, IERC7093.RecoveryConfigArg[] calldata recoveryConfigArgs) external;

    function startRecovery(
        address account,
        uint256 configIndex,
        bytes calldata newOwner,
        IERC7093.Permission[] calldata permissions
    ) external;

    function executeRecovery(address account, uint256 configIndex) external;

    function cancelRecovery(address account, uint256 configIndex) external;

    function cancelRecoveryByGuardians(
        address account,
        uint256 configIndex,
        IERC7093.Permission[] calldata permissions
    ) external;

    function isGuardian(address account, uint256 configIndex, IERC7093.Identity calldata guardian)
        external
        view
        returns (bool);

    function getRecoveryConfigs(address account)
        external
        view
        returns (IERC7093.RecoveryConfigArg[] memory recoveryConfigArgs);

    function getRecoveryNonce(address account) external view returns (uint256 nonce);

    function getRecoveryStatus(address account, uint256 configIndex)
        external
        view
        returns (bool isRecovering, uint48 expiryTime);
}
