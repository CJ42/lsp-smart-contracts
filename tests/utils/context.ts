import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { BigNumber } from 'ethers';
import {
  KeyManagerInternalTester,
  LSP6KeyManager,
  LSP6KeyManagerV2,
  UniversalProfile,
} from '../../types';

export type LSP6TestContext = {
  accounts: SignerWithAddress[];
  mainController: SignerWithAddress;
  universalProfile: UniversalProfile;
  keyManager: LSP6KeyManager | LSP6KeyManagerV2;
  initialFunding?: BigNumber;
};

export type LSP6InternalsTestContext = {
  accounts: SignerWithAddress[];
  mainController: SignerWithAddress;
  universalProfile: UniversalProfile;
  keyManagerInternalTester: KeyManagerInternalTester;
};
