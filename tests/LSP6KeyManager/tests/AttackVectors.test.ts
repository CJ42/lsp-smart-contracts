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

  describe.only("reentrancy: malicious contract with permission CALL + TRANSFERVALUE drains all funds via `receive()` function", () => {
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
};
