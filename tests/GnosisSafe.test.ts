import { ethers } from "hardhat";
import { expect } from "chai";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";

import { OPERATION_TYPES } from "../constants";

import {
  Account,
  Account__factory,
  MultiSig,
  MultiSig__factory,
  GnosisSafe,
  GnosisSafe__factory,
  GnosisSafeProxy,
  GnosisSafeProxy__factory,
} from "../types";
import { Contract } from "ethers";

describe("Account", () => {
  let accounts: SignerWithAddress[];
  let multisigOwners: SignerWithAddress[];
  let myAccount: Account;
  let myMultiSig: GnosisSafe;

  before(async () => {
    accounts = await ethers.getSigners();

    multisigOwners = accounts.slice(0, 3);

    const MultiSigFactory = await ethers.getContractFactory("GnosisSafe");

    const MultiSigSingleton = await MultiSigFactory.deploy();

    const multisigInstance = await new GnosisSafeProxy__factory(
      accounts[0]
    ).deploy(MultiSigSingleton.address);

    myMultiSig = MultiSigFactory.attach(multisigInstance.address) as GnosisSafe;

    // setup the Gnosis Multisig
    await myMultiSig.setup(
      multisigOwners.map((owner) => owner.address),
      1,
      ethers.constants.AddressZero,
      "0x",
      ethers.constants.AddressZero,
      ethers.constants.AddressZero,
      0,
      ethers.constants.AddressZero
    );

    // deploy my Account with the Multisig as the owner
    myAccount = await new Account__factory(accounts[0]).deploy(
      myMultiSig.address,
      { value: ethers.utils.parseEther("10") }
    );
  });

  it("send money to this user through the multisig", async function () {
    const recipient = accounts[5].address;
    const amount = ethers.utils.parseEther("1");

    const transferPayload = myAccount.interface.encodeFunctionData(
      "execute(uint256,address,uint256,bytes)",
      [OPERATION_TYPES.CALL, recipient, amount, "0x"]
    );

    const signature = multisigOwners[0].signMessage(transferPayload);

    await myMultiSig.execTransaction(
      myAccount.address,
      0,
      transferPayload,
      0,
      1_000_000,
      0,
      0,
      ethers.constants.AddressZero,
      ethers.constants.AddressZero,
      signature
    );
  });
});
