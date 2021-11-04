import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { ethers } from "hardhat";

import {
  Destructor,
  Destructor__factory,
  KeyManager,
  KeyManager__factory,
  UniversalProfile,
  UniversalProfile__factory,
} from "../build/types";

import { ALL_PERMISSIONS_SET, KEYS, OPERATIONS, PERMISSIONS } from "./utils/keymanager";

describe("Security related tests", () => {
  let provider = ethers.provider;

  let accounts: SignerWithAddress[] = [];
  let universalProfile: UniversalProfile;
  let destructor: Destructor;

  let owner, attacker: SignerWithAddress;

  let destructorPayload: string;

  describe.skip("Interacting via UP directly", () => {
    beforeAll(async () => {
      accounts = await ethers.getSigners();
      owner = accounts[0];
      attacker = accounts[1];

      universalProfile = await new UniversalProfile__factory(owner).deploy(owner.address);
      destructor = await new Destructor__factory(attacker).deploy();

      destructorPayload = destructor.interface.encodeFunctionData("doWork");
    });

    it("UP contract should contain some bytecode", async () => {
      let result = await provider.getCode(universalProfile.address);
      expect(result !== "0x");
    });

    it("Owner should be able to destroy its UP via DELEGATECALL", async () => {
      await universalProfile
        .connect(owner)
        .execute(OPERATIONS.DELEGATECALL, destructor.address, 0, destructorPayload);

      let result = await provider.getCode(universalProfile.address);
      expect(result !== "0x");
    });

    xit("should not be possible to call a function on the UP after destroying it", async () => {
      await universalProfile
        .connect(owner)
        .execute(OPERATIONS.DELEGATECALL, destructor.address, 0, destructorPayload);

      await universalProfile
        .connect(owner)
        .setData(
          [ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Some key"))],
          [ethers.utils.hexlify(ethers.utils.toUtf8Bytes("some value"))]
        );
    });

    // function call to a non-contract account
  });

  describe.skip("Interacting via KeyManager", () => {
    let keyManager: KeyManager;

    beforeEach(async () => {
      accounts = await ethers.getSigners();
      owner = accounts[0];
      attacker = accounts[1];

      universalProfile = await new UniversalProfile__factory(owner).deploy(owner.address);
      destructor = await new Destructor__factory(attacker).deploy();

      destructorPayload = destructor.interface.encodeFunctionData("doWork");

      keyManager = await new KeyManager__factory(owner).deploy(universalProfile.address);

      // owner permissions
      await universalProfile
        .connect(owner)
        .setData(
          [KEYS.PERMISSIONS + owner.address.substr(2)],
          [ethers.utils.hexZeroPad(ALL_PERMISSIONS_SET, 32)]
        );

      // we call it `attacker` here to "recognize the caller in the code"
      // but this can be anyone with the DELEGATECALL permission
      await universalProfile
        .connect(owner)
        .setData(
          [KEYS.PERMISSIONS + attacker.address.substr(2)],
          [ethers.utils.hexZeroPad(PERMISSIONS.DELEGATECALL, 32)]
        );

      // switch account management to KeyManager
      await universalProfile.connect(owner).transferOwnership(keyManager.address);
    });

    it("anyone with permission DELEGATECALL might be able to destroy the UP", async () => {
      let maliciousPayload = universalProfile.interface.encodeFunctionData("execute", [
        OPERATIONS.DELEGATECALL,
        destructor.address,
        0,
        destructorPayload,
      ]);

      await keyManager.connect(attacker).execute(maliciousPayload);
      let result = await provider.getCode(universalProfile.address);

      expect(result).toEqual("0x");
    });

    it("attacker should have received all LYXs from UP after `selfdestruct`", async () => {
      await owner.sendTransaction({
        to: universalProfile.address,
        value: ethers.utils.parseEther("5"),
      });

      let initialUPBalance = await provider.getBalance(universalProfile.address);
      //   console.log("initialUPBalance: ", ethers.utils.formatEther(initialUPBalance));
      let initialAttackerBalance = await provider.getBalance(attacker.address);

      expect(initialUPBalance).toEqual(ethers.utils.parseEther("5"));

      let maliciousPayload = universalProfile.interface.encodeFunctionData("execute", [
        OPERATIONS.DELEGATECALL,
        destructor.address,
        0,
        destructorPayload,
      ]);

      await keyManager.connect(attacker).execute(maliciousPayload);

      let newUPBalance = await provider.getBalance(universalProfile.address);
      //   console.log("initialUPBalance: ", ethers.utils.formatEther(initialUPBalance));
      let newAttackerBalance = await provider.getBalance(attacker.address);

      expect(newUPBalance).toEqual(ethers.utils.parseEther("0"));

      //   console.log(initialAttackerBalance.add(initialUPBalance).toString());
      //   expect(newAttackerBalance).toEqual(ethers.utils.parseEther());
      //   let result = await provider.getCode(universalProfile.address);

      //   expect(result).toEqual("0x");
    });
  });
});
