// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;

// interfaces
import {IERC725Y} from "@erc725/smart-contracts/contracts/interfaces/IERC725Y.sol";
import {ILSP20CallVerifier as ILSP20} from "../LSP20CallVerification/ILSP20CallVerifier.sol";

// libraries
import {LSP2Utils} from "../LSP2ERC725YJSONSchema/LSP2Utils.sol";
import {LSP6Utils} from "../LSP6KeyManager/LSP6Utils.sol";

// constants
import {
    _LSP6KEY_ADDRESSPERMISSIONS_ARRAY_PREFIX,
    _LSP6KEY_ADDRESSPERMISSIONS_PREFIX,
    _LSP6KEY_ADDRESSPERMISSIONS_PERMISSIONS_PREFIX,
    _LSP6KEY_ADDRESSPERMISSIONS_ALLOWEDCALLS_PREFIX,
    _LSP6KEY_ADDRESSPERMISSIONS_AllowedERC725YDataKeys_PREFIX,
    _PERMISSION_SETDATA,
    _PERMISSION_ADDCONTROLLER,
    _PERMISSION_EDITPERMISSIONS,
    _PERMISSION_SUPER_SETDATA,
    _PERMISSION_SETDATA
} from "./LSP6Constants.sol";

import {
    _LSP20_VERIFY_CALL_SUCCESS_VALUE_WITHOUT_POST_VERIFICATION
} from "../LSP20CallVerification/LSP20Constants.sol";

// Errors
import {NoPermissionsSet} from "./LSP6Errors.sol";

// Debugging
import {console} from "hardhat/console.sol";

// Custom Permission type
type Permission is bytes32;

Permission constant _SET_DATA = Permission.wrap(_PERMISSION_SETDATA);

function contains(Permission input, Permission toCheck) pure returns (bool) {
    return
        Permission.unwrap(input) & Permission.unwrap(toCheck) == Permission.unwrap(toCheck)
            ? true
            : false;
}

function set(Permission input, Permission toAdd) pure returns (Permission) {
    return Permission.wrap(Permission.unwrap(input) | Permission.unwrap(toAdd));
}

// function unset(
//     Permission input,
//     Permission toRemove
// ) pure returns (Permission) {
//     bytes32 placeholder = ~Permission.unwrap(toRemove);

//     return Permission.wrap(Permission.unwrap(input) & placeholder);
// }

using {contains, set} for Permission;

// using {set as |} for Permission global;

contract LSP6KeyManagerV2 {
    using LSP2Utils for bytes10;
    using LSP6Utils for *;

    address _target;

    constructor(address target_) {
        _target = target_;
    }

    /// @dev This is a temporary solution to allow accepting ownership of the Key Manager during setup for Benchmark tests
    function execute(bytes calldata callData) public {
        (bool success, ) = _target.call(callData);

        if (!success) revert("execute call failed!");

        return;
    }

    function lsp20VerifyCall(
        address /* requestor */,
        address targetContract,
        address caller,
        uint256 /* msgValue */,
        bytes calldata callData
    ) external virtual returns (bytes4) {
        console.log(gasleft());

        bytes4 erc725Function = bytes4(callData);

        if (erc725Function == IERC725Y.setData.selector) {
            (bytes32 inputDataKey, bytes memory dataValue) = abi.decode(
                callData[4:],
                (bytes32, bytes)
            );

            _verifyCanSetData(inputDataKey, targetContract, caller);

            IERC725Y(targetContract).setData(inputDataKey, dataValue);

            return _LSP20_VERIFY_CALL_SUCCESS_VALUE_WITHOUT_POST_VERIFICATION;
        }

        revert("unknown path");
    }

    function _verifyCanSetData(
        bytes32 inputDataKey,
        address targetContract,
        address caller
    ) internal view {
        console.log(gasleft());

        // AddressPermissions:Permissions:<caller>
        bytes32 permissions = IERC725Y(targetContract).getPermissionsFor(caller);

        if (permissions == bytes32(0)) revert NoPermissionsSet(caller);

        console.log(gasleft());
        Permission callerPermissions = Permission.wrap(permissions);
        console.log(gasleft());

        // bytes32[] memory dataKeysToFetch = new bytes32[](2);

        if (bytes12(inputDataKey) == _LSP6KEY_ADDRESSPERMISSIONS_PERMISSIONS_PREFIX) {
            // AddressPermissions:Permissions:<address>
            // save gas by avoiding redundants or unecessary external calls to fetch values from the `target` storage.
            bool hasBothAddControllerAndEditPermissions = callerPermissions.contains(
                // TODO: save these constants as user-defined value types
                Permission.wrap(_PERMISSION_ADDCONTROLLER | _PERMISSION_EDITPERMISSIONS)
            );

            if (hasBothAddControllerAndEditPermissions) return;

            bytes32 permissionRequired = Permission.unwrap(callerPermissions) == bytes32(0)
                ? _PERMISSION_ADDCONTROLLER
                : _PERMISSION_EDITPERMISSIONS;

            if (!callerPermissions.contains(Permission.wrap(permissionRequired))) {
                revert("Cannot set controller permissions!");
            }
        } else {
            // TODO: save these constants as user-defined value types

            console.log(gasleft());

            // Skip if controller has SUPER SETDATA permissions
            if (callerPermissions.contains(Permission.wrap(_PERMISSION_SUPER_SETDATA))) return;

            console.log(gasleft());

            // Check if controller has permission SETDATA
            if (!callerPermissions.contains(Permission.wrap(_PERMISSION_SETDATA))) {
                revert("Not authorised to set data!");
            }

            console.log(gasleft());

            // AddressPermissions:AllowedERC725YDataKeys:<caller>
            // dataKeysToFetch[0] = _LSP6KEY_ADDRESSPERMISSIONS_AllowedERC725YDataKeys_PREFIX
            //     .generateMappingWithGroupingKey(bytes20(caller));

            // value for `inputDataKey`
            // dataKeysToFetch[1] = inputDataKey;

            // bytes[] memory currentDataValues = IERC725Y(targetContract).getDataBatch(
            //     dataKeysToFetch
            // );

            // 3. Check if it is an Allowed ERC725Y Data Keys
            if (
                !_isAllowedERC725YDataKey({
                    dataKeyToVerify: inputDataKey,
                    // TODO: user-defined value type for Allowed ERC725Y Data Keys?
                    allowedERC725YDataKeysCompacted: IERC725Y(targetContract)
                        .getAllowedERC725YDataKeysFor(caller)
                })
            ) {
                revert("Not allowed ERC725Y Data Key");
            }

            console.log(gasleft());
        }
    }

    // TODO: make this a library function
    function _isAllowedERC725YDataKey(
        bytes32 dataKeyToVerify,
        bytes memory allowedERC725YDataKeysCompacted
    ) internal pure returns (bool) {
        if (allowedERC725YDataKeysCompacted.length == 0) {
            revert("No ERC725Y Data Keys Allowed");
        }

        uint256 pointer;

        // information extracted from each Allowed ERC725Y Data Key.
        uint256 length;
        bytes32 allowedKey;
        bytes32 mask; // TODO: is this necessary to cache in local variable? Or is that more stack manipulation?

        while (pointer < allowedERC725YDataKeysCompacted.length) {
            // concatenate with Bitwise OR
            length = uint16(
                bytes2(
                    bytes2(allowedERC725YDataKeysCompacted[pointer]) |
                        bytes2(allowedERC725YDataKeysCompacted[pointer + 1] >> 8)
                )
            );

            if (length == 0 || length > 32) {
                revert("Invalid encoded Allowed ERC725Y Data Keys: couldn't DECODE from storage");
            }

            assembly {
                mask := shl(
                    mul(sub(32, length), 8),
                    0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                )

                let offset := add(add(pointer, 2), 32)
                let memoryAt := mload(add(allowedERC725YDataKeysCompacted, offset))
                // MLOAD loads 32 bytes word, so we need to keep only the `length` number of bytes that makes up the allowed data key.
                allowedKey := and(memoryAt, mask)
            }

            if (allowedKey == (dataKeyToVerify & mask)) return true;

            // move the pointer to the index of the next allowed data key
            unchecked {
                pointer = pointer + (length + 2);
            }
        }

        return false;
    }
}

// else if (bytes12(inputDataKey) == _LSP6KEY_ADDRESSPERMISSIONS_ALLOWEDCALLS_PREFIX) {
//     // AddressPermissions:AllowedCalls:<address>
//     // ...
// } else if (
//     bytes12(inputDataKey) == _LSP6KEY_ADDRESSPERMISSIONS_AllowedERC725YDataKeys_PREFIX
// ) {
//     // AddressPermissions:AllowedERC725YKeys:<address>
//     //
