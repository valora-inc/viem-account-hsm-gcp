import {
  parseEther,
  parseGwei,
  recoverTransactionAddress,
  recoverTypedDataAddress,
  verifyHash,
  verifyMessage,
} from 'viem'
import { TYPED_DATA } from '../test/values'
import { gcpHsmToAccount } from './gcpHsmToAccount'

const GCP_HSM_KEY_NAME =
  'projects/valora-viem-hsm-test/locations/global/keyRings/test/cryptoKeys/hsm/cryptoKeyVersions/1'

describe('gcpHsmToAccount', () => {
  it('returns a valid viem account when given a known hsm key', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: GCP_HSM_KEY_NAME,
    })
    expect(gcpHsmAccount).toEqual({
      address: '0x6AD01Ac6841b67f27DC1A039FefBF5804003d6a4',
      publicKey:
        '0x04b7ff0468ad921a192f9ad1eb8d979aacd1e27c86dccc5172fc48e587fb46e4520a52ddcfb10e8f48841fa758930a1e1f15dd12c51e1868f38ab1352d2ee9b132',
      sign: expect.any(Function),
      signMessage: expect.any(Function),
      signTransaction: expect.any(Function),
      signTypedData: expect.any(Function),
      source: 'gcpHsm',
      type: 'local',
    })
  })

  it('throws an error when given an unknown hsm key', async () => {
    await expect(
      gcpHsmToAccount({
        hsmKeyVersion: 'an-unknown-key',
      }),
    ).rejects.toThrow(
      /3 INVALID_ARGUMENT: Resource name 'an-unknown-key' does not match pattern/,
    )
  })

  it('signs a message', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: GCP_HSM_KEY_NAME,
    })

    const message = 'hello world'
    const signature = await gcpHsmAccount.signMessage({ message })

    await expect(
      verifyMessage({
        address: gcpHsmAccount.address,
        message,
        signature,
      }),
    ).resolves.toBeTruthy()
  })

  it('signs a hash', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: GCP_HSM_KEY_NAME,
    })

    const hash =
      '0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68'
    const signature = await gcpHsmAccount.sign!({ hash })

    await expect(
      verifyHash({
        address: gcpHsmAccount.address,
        hash: hash,
        signature: signature,
      }),
    ).resolves.toBeTruthy()
  })

  it('signs a transaction', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: GCP_HSM_KEY_NAME,
    })
    const signedTx = await gcpHsmAccount.signTransaction({
      chainId: 1,
      maxFeePerGas: parseGwei('20'),
      gas: 21000n,
      to: '0x0000000000000000000000000000000000007e57',
      value: parseEther('0.001'),
    })

    await expect(
      recoverTransactionAddress({
        serializedTransaction: signedTx,
      }),
    ).resolves.toBe(gcpHsmAccount.address)
  })

  it('signs typed data', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: GCP_HSM_KEY_NAME,
    })
    const signature = await gcpHsmAccount.signTypedData(TYPED_DATA)

    await expect(
      recoverTypedDataAddress({
        ...TYPED_DATA,
        signature,
      }),
    ).resolves.toBe(gcpHsmAccount.address)
  })
})
