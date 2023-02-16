// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {UniversalProfile} from "./UniversalProfile.sol";

// overloaded selectors
import {SETDATA_SELECTOR, EXECUTE_SELECTOR} from "@erc725/smart-contracts/contracts/constants.sol";

interface IReadOnlyDelegateCall {
    function readOnlyDelegateCall(address logic, bytes memory callData)
        external
        view
        returns (bytes memory result);
}

contract MyAccount is UniversalProfile {
    ReverseProxy_SetData reverseProxy_setData;
    ReverseProxy_Execute reverseProxy_execute;

    constructor(
        address newOwner_,
        ReverseProxy_SetData reverseProxySetData_,
        ReverseProxy_Execute reverseProxyExecute_
    ) UniversalProfile(newOwner_) {
        reverseProxy_setData = reverseProxySetData_;
        reverseProxy_execute = reverseProxyExecute_;
    }

    /// @dev WARNING! this function should only be called by the contract itself!
    function readOnlyDelegateCall(address logic, bytes memory callData)
        external
        returns (bytes memory)
    {
        ///
        /// @todo: put a guard in ERC725X.execute so that this function cannot be called from there
        require(msg.sender == address(this), "only self!");

        (bool success, bytes memory returnOrRevertData) = logic.delegatecall(callData);

        // if the delegatecall failed
        if (!success) {
            // Bubble up reverts
            assembly {
                revert(add(returnOrRevertData, 32), mload(returnOrRevertData))
            }
        }

        // if the delegatecall succeeded, return the result
        return returnOrRevertData;
    }

    function setData(bytes32 dataKey, bytes memory dataValue) public override {
        if (msg.sender != owner()) {
            // 1. retrieve the address of the reverse proxy to call for verification.
            address reverseProxyAuth = address(reverseProxy_setData);

            // 2. delegatecall to a reverse "server/contract" setup for permission + access control checks
            // we cast to the `IReadOnlyDelegateCall` interface where `doDelegateCall()` is defined as `view`.
            // the solc compiler will generate a staticcall, preventing any state alteration in the current context.
            bytes memory returnData = IReadOnlyDelegateCall(address(this)).readOnlyDelegateCall(
                reverseProxyAuth,
                msg.data // we forward all the calldata to be analyzed for checking the permissions
            );

            // 3. verify if the access control check passed
            // -----
            // for the access control to pass, the reverse server must return exactly the same function selector
            // of the function we are currently running.
            // in this case --> 1st 4x bytes of keccak256("setData(bytes32,bytes)" = 0x7f23690c

            // 3.1 sanity check
            require(returnData.length == 4, "invalid access control result!");
            bytes4 accessControlResult = bytes4(returnData);

            // 3.2 verification
            if (accessControlResult != SETDATA_SELECTOR) {
                revert("Access Control/Permission check failed");
            }
        }
        _setData(dataKey, dataValue);
    }

    function execute(
        uint256 operationType,
        address target,
        uint256 value,
        bytes memory data
    ) public payable override returns (bytes memory) {
        if (msg.sender != owner()) {
            address reverseProxyAuth = address(reverseProxy_setData);

            bytes memory returnData = IReadOnlyDelegateCall(address(this)).readOnlyDelegateCall(
                reverseProxyAuth,
                msg.data // we forward all the calldata to be analyzed for checking the permissions
            );
        }

        if (msg.value != 0) emit ValueReceived(msg.sender, msg.value);
        return _execute(operationType, target, value, data);
    }
}

/// @dev this contract is intended to be called only via delegatecall
contract ReverseProxy_SetData {
    // bytes4(keccak256("setData(bytes32,bytes)")
    bytes4 constant MAGIC_VALUE = 0x7f23690c;

    fallback() external payable {
        // verification logic runs here
        // e.g: any access control check, such as verifying the permissions

        // NB: this will be cheaper here because since we are doing delegatecall,
        // we are in the same context as the contract storage

        // _verifyCanSetData()

        assembly {
            mstore(0, MAGIC_VALUE)
            return(0, 4)
        }
    }
}

/// @dev this contract is intended to be called only via delegatecall
contract ReverseProxy_Execute {
    bytes4 constant MAGIC_VALUE = EXECUTE_SELECTOR;

    fallback() external payable {
        assembly {
            mstore(0, MAGIC_VALUE)
            return(0, 4)
        }
    }
}
