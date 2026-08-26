// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Simple deterministic target used to prove the SmartAccount actually
///         executes transactions (sets state, receives ETH, and can revert).
contract MockTarget {
    uint256 public value;
    event ValueSet(uint256 value);
    event Received(address sender, uint256 amount);

    function setValue(uint256 v) external {
        value = v;
        emit ValueSet(v);
    }

    function setValueWithValue(uint256 v) external payable {
        value = v;
        emit ValueSet(v);
    }

    /// @notice Always reverts, used to test that failed target calls bubble up.
    function fail() external pure {
        revert("MockTarget: intentional failure");
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }
}
