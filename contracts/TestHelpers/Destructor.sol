// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.7;

contract Destructor {

    address destructor;

    constructor() {
        destructor = msg.sender;
    }

    function doWork() external {
        selfdestruct(payable(destructor));
    }
}