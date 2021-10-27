import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { ethers } from "hardhat";

import {
  UniversalProfileExtended,
  UniversalProfileExtended__factory,
  KeyManager,
  KeyManager__factory,
} from "../build/types";

import { ALL_PERMISSIONS_SET, KEYS } from "./utils/keymanager";

describe("UP Selectors", () => {
  let accounts: SignerWithAddress[] = [];
  let upExtended: UniversalProfileExtended, keyManager: KeyManager;

  let owner: SignerWithAddress;

  beforeAll(async () => {
    accounts = await ethers.getSigners();
    owner = accounts[0];

    upExtended = await new UniversalProfileExtended__factory(owner).deploy(owner.address);
    keyManager = await new KeyManager__factory(owner).deploy(upExtended.address);

    console.log("extended UP functions:", upExtended.functions);

    // owner permissions
    await upExtended["setData(bytes32[],bytes[])"](
      [KEYS.PERMISSIONS + owner.address.substr(2)],
      [ALL_PERMISSIONS_SET]
    );

    // switch account management to KeyManager
    await upExtended.connect(owner).transferOwnership(keyManager.address);
  });

  describe("> Testing payload for ERC725 overloaded functions", () => {
    it("`setData(bytes32[],bytes[])` => pass / `setData(bytes32[],bytes[],string)` => fails", async () => {
      // regular setData
      let key = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("SomeKey"));
      let value = ethers.utils.hexlify(ethers.utils.toUtf8Bytes("Some Value"));

      let payload = upExtended.interface.encodeFunctionData("setData(bytes32[],bytes[])", [
        [key],
        [value],
      ]);

      await keyManager.connect(owner).execute(payload);
      let [fetchedResult] = await upExtended.callStatic.getData([key]);
      expect(fetchedResult).toEqual(value);

      // overloaded setData
      let payloadOverloaded = upExtended.interface.encodeFunctionData(
        "setData(bytes32[],bytes[],string)",
        [[key], [value], "Some message for the event"]
      );

      await expect(keyManager.connect(owner).execute(payloadOverloaded)).toBeRevertedWith(
        // note that if we would not have this last `else` conditional check in the contract,
        // the overloaded function would (probably) pass and it would setData in the contract,
        // even if the caller does not have permission to setData
        // since no check would be made
        "KeyManager:_checkPermissions: unknown function selector from ERC725 account"
      );
      console.log("payload setData(bytes32[],bytes[]): ", payload);
      console.log("payloadOverloaded setData(bytes32[],bytes[],string): ", payloadOverloaded);
    });
  });
});
