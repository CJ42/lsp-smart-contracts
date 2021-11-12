// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.6;

// modules
import "@openzeppelin/contracts/utils/introspection/ERC165Storage.sol";
import "../../submodules/ERC725/implementations/contracts/ERC725/ERC725.sol";

// interfaces
import "./ILSP6-KeyManager.sol";

// libraries
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

error NotEnoughPermissions(address caller, bytes32 missingPermissions);

abstract contract KeyManagerV2Core is ILSP6, ERC165Storage {

    // prettier-ignore
    /* solhint-disable */
    // PERMISSION KEYS

    bytes8 internal constant _SET_PERMISSIONS           = 0x4b80742d00000000;         // AddressPermissions:<...>
    bytes12 internal constant _ADDRESS_PERMISSIONS      = 0x4b80742d0000000082ac0000; // AddressPermissions:Permissions:<address> --> bytes32
    bytes12 internal constant _ADDRESS_ALLOWEDADDRESSES = 0x4b80742d00000000c6dd0000; // AddressPermissions:AllowedAddresses:<address> --> address[]
    bytes12 internal constant _ADDRESS_ALLOWEDFUNCTIONS = 0x4b80742d000000008efe0000; // AddressPermissions:AllowedFunctions:<address> --> bytes4[]
    bytes12 internal constant _ADDRESS_ALLOWEDSTANDARDS = 0x4b80742d000000003efa0000; // AddressPermissions:AllowedStandards:<address> --> bytes4[]
    /* solhint-enable */

    // prettier-ignore
    // PERMISSIONS VALUES
    bytes32 internal constant _PERMISSION_CHANGEOWNER          = 0x0000000000000000000000000000000000000000000000000000000000000001;   // [240 x 0 bits...] 0000 0000 0000 0001
    bytes32 internal constant _PERMISSION_CHANGEPERMISSIONS    = 0x0000000000000000000000000000000000000000000000000000000000000002;   // [      ...      ] .... .... .... 0010
    bytes32 internal constant _PERMISSION_SETDATA              = 0x0000000000000000000000000000000000000000000000000000000000000004;   // [      ...      ] .... .... .... 0100
    bytes32 internal constant _PERMISSION_CALL                 = 0x0000000000000000000000000000000000000000000000000000000000000008;   // [      ...      ] .... .... .... 1000
    bytes32 internal constant _PERMISSION_STATICCALL           = 0x0000000000000000000000000000000000000000000000000000000000000010;   // [      ...      ] .... .... 0001 ....
    bytes32 internal constant _PERMISSION_DELEGATECALL         = 0x0000000000000000000000000000000000000000000000000000000000000020;   // [      ...      ] .... .... 0010 ....
    bytes32 internal constant _PERMISSION_DEPLOY               = 0x0000000000000000000000000000000000000000000000000000000000000040;   // [      ...      ] .... .... 0100 ....
    bytes32 internal constant _PERMISSION_TRANSFERVALUE        = 0x0000000000000000000000000000000000000000000000000000000000000080;   // [      ...      ] .... .... 1000 ....
    bytes32 internal constant _PERMISSION_SIGN                 = 0x0000000000000000000000000000000000000000000000000000000000000100;   // [      ...      ] .... 0001 .... ....
}