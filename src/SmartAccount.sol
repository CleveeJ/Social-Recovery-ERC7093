// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ISmartAccount} from "./interfaces/ISmartAccount.sol";

/// @title SmartAccount
/// @notice ERC-4337 / ERC-7579 account. Normal authorization lives in the validator; recovery in the executor.
contract SmartAccount is Initializable, AccountERC7579, ISmartAccount {
    address public override owner;
    IEntryPoint private immutable _entryPoint;

    event OwnerChanged(address indexed newOwner);

    error ZeroOwner();
    error ZeroEntryPoint();
    error NotAuthorizedRecovery(address caller);

    constructor(IEntryPoint entryPoint_, address initialOwner) {
        if (address(entryPoint_) == address(0)) revert ZeroEntryPoint();
        if (initialOwner == address(0)) revert ZeroOwner();
        _entryPoint = entryPoint_;
        owner = initialOwner;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function initializeAccount(address validator, bytes calldata validatorData) external initializer {
        _installModule(MODULE_TYPE_VALIDATOR, validator, validatorData);
    }

    /// @notice Rotate owner after validated recovery. Only an installed executor, or the account itself.
    function recoverOwner(bytes calldata newOwner) external override {
        if (msg.sender != address(this) && !this.isModuleInstalled(MODULE_TYPE_EXECUTOR, msg.sender, "")) {
            revert NotAuthorizedRecovery(msg.sender);
        }
        address recovered = abi.decode(newOwner, (address));
        if (recovered == address(0)) revert ZeroOwner();
        owner = recovered;
        emit OwnerChanged(recovered);
    }
}
