// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {UniversalProfile} from "./UniversalProfile.sol";
import {GnosisSafeProxy} from "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxy.sol";

contract Account is UniversalProfile {
    constructor(address newOwner) payable UniversalProfile(newOwner) {}

    modifier reverseOwner() {
        if (msg.sender != owner()) {
            (bool success, ) = owner().call(msg.data);
        } else {
            _;
        }
    }

    function execute(
        uint256 operationType,
        address target,
        uint256 value,
        bytes memory data
    ) public payable override reverseOwner returns (bytes memory result) {
        if (msg.value != 0) emit ValueReceived(msg.sender, msg.value);
        return _execute(operationType, target, value, data);
    }
}

contract MultiSig is GnosisSafeProxy {
    constructor(address _singleton) GnosisSafeProxy(_singleton) {}
}
