// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "../UniversalProfile.sol";


contract UniversalProfileExtended is UniversalProfile {

    event CustomEvent(string);

    /* solhint-disable no-empty-blocks */
    constructor(address newOwner) UniversalProfile(newOwner) {}

    // this one function selector
    // 251fbf35: setData(bytes32[],bytes[],string)
    function setData(bytes32[] memory _keys, bytes[] memory _values, string memory eventMessage) 
        public
        onlyOwner
    {
        // this is the initial function selector
        // 14a6e293: setData(bytes32[],bytes[])
        setData(_keys, _values);
        emit CustomEvent(eventMessage);
    }

}