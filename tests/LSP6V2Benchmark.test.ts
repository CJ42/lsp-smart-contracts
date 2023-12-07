import fs from 'fs';
import { ethers } from 'hardhat';
import { expect } from 'chai';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';

import {
  LSP1UniversalReceiverDelegateUP,
  LSP1UniversalReceiverDelegateUP__factory,
  LSP6KeyManagerV2,
  LSP6KeyManagerV2__factory,
  UniversalProfile,
  UniversalProfile__factory,
} from '../types';
import { BigNumber } from 'ethers';
import { ERC725YDataKeys } from '../constants';
import { setupKeyManager } from './utils/fixtures';

export type LSP6TestContext = {
  accounts: SignerWithAddress[];
  mainController: SignerWithAddress;
  universalProfile: UniversalProfile;
  keyManager: LSP6KeyManagerV2;
  initialFunding?: BigNumber;
};

const buildLSP6TestContext = async (initialFunding?: BigNumber): Promise<LSP6TestContext> => {
  const accounts = await ethers.getSigners();
  const mainController = accounts[0];

  const universalProfile = await new UniversalProfile__factory(mainController).deploy(
    mainController.address,
    {
      value: initialFunding,
    },
  );
  const keyManager = await new LSP6KeyManagerV2__factory(mainController).deploy(
    universalProfile.address,
  );

  return { accounts, mainController, universalProfile, keyManager };
};

describe('⛽📊 Gas Benchmark', () => {
  let gasBenchmark;

  let lsp1Delegate;

  before('setup benchmark file', async () => {
    gasBenchmark = JSON.parse(fs.readFileSync('./scripts/ci/gas_benchmark_template.json', 'utf8'));
  });

  after(async () => {
    fs.writeFileSync('./gas_benchmark_lsp6v2_result.json', JSON.stringify(gasBenchmark, null, 2));
  });

  describe('Deployment costs', () => {
    it('deploy contracts + save deployment costs', async () => {
      const accounts = await ethers.getSigners();

      // Universal Profile
      const universalProfile = await new UniversalProfile__factory(accounts[0]).deploy(
        accounts[0].address,
      );

      const universalProfileDeployTransaction = universalProfile.deployTransaction;
      const universalProfileDeploymentReceipt = await universalProfileDeployTransaction.wait();

      gasBenchmark['deployment_costs']['UniversalProfile'] =
        universalProfileDeploymentReceipt.gasUsed.toNumber();

      // Key Manager
      const keyManager = await new LSP6KeyManagerV2__factory(accounts[0]).deploy(
        universalProfile.address,
      );

      const keyManagerDeployTransaction = keyManager.deployTransaction;
      const keyManagerDeploymentReceipt = await keyManagerDeployTransaction?.wait();

      gasBenchmark['deployment_costs']['KeyManager'] =
        keyManagerDeploymentReceipt?.gasUsed.toNumber();

      // LSP1 Delegate
      lsp1Delegate = await new LSP1UniversalReceiverDelegateUP__factory(accounts[0]).deploy();

      const lsp1DelegateDeployTransaction = lsp1Delegate.deployTransaction;
      const lsp1DelegateDeploymentReceipt = await lsp1DelegateDeployTransaction.wait();

      gasBenchmark['deployment_costs']['LSP1DelegateUP'] =
        lsp1DelegateDeploymentReceipt.gasUsed.toNumber();
    });
  });

  describe('KeyManager', () => {
    describe('Testing simple `setData(bytes32,bytes)` on Key Manager V2', () => {
      describe('main controller (this browser extension)', () => {
        let context: LSP6TestContext;

        let recipientEOA: SignerWithAddress;

        before('setup', async () => {
          context = await buildLSP6TestContext(ethers.utils.parseEther('50'));

          recipientEOA = context.accounts[1];

          await setupKeyManager(
            context,
            [ERC725YDataKeys.LSP1.LSP1UniversalReceiverDelegate],
            [lsp1Delegate.address],
          );
        });

        it('Update profile details (LSP3Profile metadata)', async () => {
          const dataKey = ERC725YDataKeys.LSP3['LSP3Profile'];
          const dataValue =
            '0x6f357c6a820464ddfac1bec070cc14a8daf04129871d458f2ca94368aae8391311af6361696670733a2f2f516d597231564a4c776572673670456f73636468564775676f3339706136727963455a4c6a7452504466573834554178';

          const tx = await context.universalProfile
            .connect(context.mainController)
            .setData(dataKey, dataValue);

          const receipt = await tx.wait();

          gasBenchmark['runtime_costs']['KeyManager_owner']['setData']['case_1'][
            'main_controller'
          ] = receipt.gasUsed.toNumber();
        });
      });

      describe('controllers with some restrictions', async () => {
        // ...
      });
    });
  });
});
