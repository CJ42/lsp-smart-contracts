import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";

import {
  MaliciousAccount,
  MaliciousAccount__factory,
  Reentrancy,
  Reentrancy__factory,
  TargetContract,
  TargetContract__factory,
  UniversalProfile,
  UniversalProfile__factory,
} from "../../../types";

import {
  ALL_PERMISSIONS_SET,
  ERC725YKeys,
  OPERATIONS,
  PERMISSIONS,
} from "../../../constants";

import { LSP6TestContext } from "../../utils/context";
import { setupKeyManager } from "../../utils/fixtures";

import {
  provider,
  EMPTY_PAYLOAD,
  NoPermissionsSetError,
  ONE_ETH,
} from "../../utils/helpers";

export const testAttackVectors = (
  buildContext: () => Promise<LSP6TestContext>
) => {
  let context: LSP6TestContext;

  describe.skip("reentrancy: UP has permissions for itself and re-enters its own KeyManager via `ERC725X.execute(...)`", () => {
    let maliciousCaller: SignerWithAddress;

    beforeEach(async () => {
      context = await buildContext();

      maliciousCaller = context.accounts[1];

      const permissionKeys = [
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          context.owner.address.substring(2),
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          maliciousCaller.address.substring(2),
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          context.universalProfile.address.substring(2),
      ];

      const permissionValues = [
        ALL_PERMISSIONS_SET,
        ethers.utils.hexZeroPad(PERMISSIONS.CALL, 32),
        ethers.utils.hexZeroPad(
          PERMISSIONS.CALL + PERMISSIONS.TRANSFERVALUE,
          32
        ),
      ];

      await setupKeyManager(context, permissionKeys, permissionValues);

      await context.owner.sendTransaction({
        to: context.universalProfile.address,
        value: ethers.utils.parseEther("10"),
      });
    });

    it("reentrancy", async () => {
      let initialAttackerBalance = await provider.getBalance(
        maliciousCaller.address
      );
      console.log("(before) attacker balance: ", initialAttackerBalance);

      let initialProfileBalance = await provider.getBalance(
        context.universalProfile.address
      );
      console.log("(before) profile balance: ", initialProfileBalance);

      let finalTransferPayload =
        context.universalProfile.interface.encodeFunctionData("execute", [
          OPERATIONS.CALL,
          maliciousCaller.address,
          ethers.utils.parseEther("10"),
          "0x",
        ]);

      let keyManagerPayload = context.keyManager.interface.encodeFunctionData(
        "execute",
        [finalTransferPayload]
      );

      let reEntrantPayload =
        context.universalProfile.interface.encodeFunctionData("execute", [
          OPERATIONS.CALL,
          context.keyManager.address,
          0,
          keyManagerPayload,
        ]);

      let tx = await context.keyManager
        .connect(maliciousCaller)
        .execute(reEntrantPayload);
      let receipt = await tx.wait();

      console.log("gas used: ", receipt.gasUsed.toNumber());

      let newAttackerBalance = await provider.getBalance(
        maliciousCaller.address
      );
      console.log("(after) attacker balance: ", newAttackerBalance);

      let newProfileBalance = await provider.getBalance(
        context.universalProfile.address
      );
      console.log("(after) profile balance: ", newProfileBalance);
    });
  });

  describe.skip("reentrancy: malicious contract with permission CALL + TRANSFERVALUE drains all funds via `receive()` function", () => {
    let attacker: SignerWithAddress;

    let attackerContract: MaliciousAccount;

    beforeEach(async () => {
      context = await buildContext();

      attacker = context.accounts[1];

      // might not know it is malicious
      attackerContract = await new MaliciousAccount__factory(attacker).deploy(
        context.keyManager.address
      );

      const permissionKeys = [
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          context.owner.address.substring(2),
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          attackerContract.address.substring(2),
      ];

      const permissionValues = [
        ALL_PERMISSIONS_SET,
        ethers.utils.hexZeroPad(
          PERMISSIONS.CALL + PERMISSIONS.TRANSFERVALUE,
          32
        ),
      ];

      await setupKeyManager(context, permissionKeys, permissionValues);

      await context.owner.sendTransaction({
        to: context.universalProfile.address,
        value: ethers.utils.parseEther("10"),
      });
    });

    it("should re-enter LYX transfer", async () => {
      let attackerContractBalanceInitial = await provider.getBalance(
        attackerContract.address
      );
      console.log(
        "attackerContractBalanceInitial: ",
        attackerContractBalanceInitial
      );

      let profileBalanceInitial = await provider.getBalance(
        context.universalProfile.address
      );
      console.log("profileBalanceInitial: ", profileBalanceInitial);

      let transferPayload =
        context.universalProfile.interface.encodeFunctionData("execute", [
          OPERATIONS.CALL,
          attackerContract.address,
          ethers.utils.parseEther("1"),
          "0x",
        ]);

      // load the "laser canon"
      //
      //          .-._______
      //          .={ . }..--""
      //         [/"`._.'    fsc
      //
      await attackerContract.loadPayload(transferPayload);

      // start firing!
      await attackerContract.connect(attacker).attack();

      let attackerContractBalanceFinal = await provider.getBalance(
        attackerContract.address
      );
      console.log(
        "attackerContractBalanceFinal: ",
        attackerContractBalanceFinal
      );

      let profileBalanceFinal = await provider.getBalance(
        context.universalProfile.address
      );
      console.log("profileBalanceFinal: ", profileBalanceFinal);
    });
  });

  // anyone with the permission CHANGEPERMISSIONS can set all the permissions
  // for itself and do whatever they want in the UP
  describe("greedy CHANGEPERMISSIONS", () => {
    let maliciousControllerCanChangePermissions: SignerWithAddress;

    beforeAll(async () => {
      context = await buildContext();

      maliciousControllerCanChangePermissions = context.accounts[1];

      const permissionKeys = [
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          context.owner.address.substring(2),
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          maliciousControllerCanChangePermissions.address.substring(2),
      ];

      const permissionValues = [
        ALL_PERMISSIONS_SET,
        ethers.utils.hexZeroPad(PERMISSIONS.CHANGEPERMISSIONS, 32),
      ];

      await setupKeyManager(context, permissionKeys, permissionValues);

      await context.owner.sendTransaction({
        to: context.universalProfile.address,
        value: ethers.utils.parseEther("10"),
      });
    });

    it("caller should be allowed to change permissions for itself", async () => {
      const key =
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
        maliciousControllerCanChangePermissions.address.substring(2);

      let [initialPermissions] = await context.universalProfile.getData([key]);
      expect(initialPermissions).toEqual(
        ethers.utils.hexZeroPad(PERMISSIONS.CHANGEPERMISSIONS, 32)
      );

      const value = ALL_PERMISSIONS_SET;

      let payload = context.universalProfile.interface.encodeFunctionData(
        "setData",
        [[key], [value]]
      );

      await context.keyManager
        .connect(maliciousControllerCanChangePermissions)
        .execute(payload);

      let [newPermissions] = await context.universalProfile.getData([key]);

      expect(newPermissions).toEqual(ALL_PERMISSIONS_SET);
    });

    describe("once caller managed to give itself ALL PERMISSIONS...", () => {
      it("should be allowed to transfer itself some LYX from the UP", async () => {
        let balanceCallerBefore = await provider.getBalance(
          maliciousControllerCanChangePermissions.address
        );
        let balanceUPBefore = await provider.getBalance(
          context.universalProfile.address
        );

        expect(balanceUPBefore).toEqBN(ethers.utils.parseEther("10"));

        let payload = context.universalProfile.interface.encodeFunctionData(
          "execute",
          [
            OPERATIONS.CALL,
            maliciousControllerCanChangePermissions.address,
            ethers.utils.parseEther("5"),
            "0x",
          ]
        );

        await context.keyManager
          .connect(maliciousControllerCanChangePermissions)
          .execute(payload);

        let balanceCallerAfter = await provider.getBalance(
          maliciousControllerCanChangePermissions.address
        );
        let balanceUPAfter = await provider.getBalance(
          context.universalProfile.address
        );
        // expect(balanceCallerAfter).toEqBN(
        //   (
        //     await provider.getBalance(
        //       maliciousControllerCanChangePermissions.address
        //     )
        //   ).add(ethers.utils.parseEther("5"))
        // );
        expect(balanceUPAfter).toEqBN(ethers.utils.parseEther("5"));
      });

      it("should be allowed to take over the control of the UP by calling `transferOwnership(...)`", async () => {
        let currentOwner = await context.universalProfile.owner();
        expect(currentOwner).toEqual(context.keyManager.address);

        let takeOverPayload =
          context.universalProfile.interface.encodeFunctionData(
            "transferOwnership",
            [maliciousControllerCanChangePermissions.address]
          );

        await context.keyManager
          .connect(maliciousControllerCanChangePermissions)
          .execute(takeOverPayload);

        let newOwner = await context.universalProfile.owner();
        expect(newOwner).toEqual(
          maliciousControllerCanChangePermissions.address
        );
      });
    });
  });

  // anyone with the permission ADDPERMISSIONS can:
  //    1) create a new controller key
  //    2) grant it ALL PERMISSIONS
  //    3) use this new controller key to take over the UP, drain funds, or do anything else
  describe("greedy ADDPERMISSIONS", () => {
    let maliciousControllerCanAddPermissions: SignerWithAddress;

    let newMaliciousControllerKey;

    beforeAll(async () => {
      context = await buildContext();

      maliciousControllerCanAddPermissions = context.accounts[1];

      const permissionKeys = [
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          context.owner.address.substring(2),
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
          maliciousControllerCanAddPermissions.address.substring(2),
      ];

      const permissionValues = [
        ALL_PERMISSIONS_SET,
        ethers.utils.hexZeroPad(PERMISSIONS.ADDPERMISSIONS, 32),
      ];

      await setupKeyManager(context, permissionKeys, permissionValues);

      await context.owner.sendTransaction({
        to: context.universalProfile.address,
        value: ethers.utils.parseEther("10"),
      });
    });

    it("can create a new controller address and give it ALL PERMISSIONS", async () => {
      newMaliciousControllerKey = ethers.Wallet.createRandom();
      newMaliciousControllerKey = newMaliciousControllerKey.connect(provider);

      // fund this new controller key
      // so that we can use it to take over the UP afterwards
      await maliciousControllerCanAddPermissions.sendTransaction({
        to: newMaliciousControllerKey.address,
        value: ethers.utils.parseEther("5"),
      });

      let key =
        ERC725YKeys.LSP6["AddressPermissions:Permissions"] +
        newMaliciousControllerKey.address.substring(2);

      let value = ALL_PERMISSIONS_SET;

      let maliciousPayload =
        context.universalProfile.interface.encodeFunctionData("setData", [
          [key],
          [value],
        ]);

      await context.keyManager
        .connect(maliciousControllerCanAddPermissions)
        .execute(maliciousPayload);

      const [result] = await context.universalProfile.getData([key]);
      expect(result).toEqual(ALL_PERMISSIONS_SET);
    });

    describe("this new malicious controller key can then do whatever it want, like...", () => {
      it("send LYX to its address", async () => {
        let balanceUPBefore = await provider.getBalance(
          context.universalProfile.address
        );
        expect(balanceUPBefore).toEqual(ethers.utils.parseEther("10"));

        let payload = context.universalProfile.interface.encodeFunctionData(
          "execute",
          [
            OPERATIONS.CALL,
            newMaliciousControllerKey.address,
            ethers.utils.parseEther("5"),
            "0x",
          ]
        );

        await context.keyManager
          .connect(newMaliciousControllerKey)
          .execute(payload);

        let balanceUPAfter = await provider.getBalance(
          context.universalProfile.address
        );
        expect(balanceUPAfter).toEqual(ethers.utils.parseEther("5"));
      });
    });
  });
};
