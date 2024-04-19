import { KeyManagementServiceClient } from '@google-cloud/kms'
import { secp256k1 } from '@noble/curves/secp256k1'
import {
  Hex,
  hexToBytes,
  parseEther,
  parseGwei,
  recoverTransactionAddress,
  recoverTypedDataAddress,
  toHex,
  verifyMessage,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import * as asn1 from 'asn1js'
import { gcpHsmToAccount } from './gcpHsmToAccount'

const PRIVATE_KEY1 =
  '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
const ACCOUNT1 = privateKeyToAccount(PRIVATE_KEY1)
const PRIVATE_KEY2 =
  '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890fdeccc'
const ACCOUNT2 = privateKeyToAccount(PRIVATE_KEY2)

const TYPED_DATA = {
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' },
      { name: 'verifyingContract', type: 'address' },
    ],
    Person: [
      { name: 'name', type: 'string' },
      { name: 'wallet', type: 'address' },
    ],
    Mail: [
      { name: 'from', type: 'Person' },
      { name: 'to', type: 'Person' },
      { name: 'contents', type: 'string' },
    ],
  },
  primaryType: 'Mail',
  domain: {
    name: 'Ether Mail',
    version: '1',
    chainId: 1n,
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
  },
  message: {
    from: {
      name: 'Cow',
      wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
    },
    to: {
      name: 'Bob',
      wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    },
    contents: 'Hello, Bob!',
  },
} as const

const MOCK_GCP_HSM_KEY_NAME =
  'projects/gcp-test-account/locations/global/keyRings/test/cryptoKeys/hsm/cryptoKeyVersions/1'

const MOCK_KEYS: Map<string, string> = new Map([
  [MOCK_GCP_HSM_KEY_NAME, PRIVATE_KEY1],
])

function derFromPublicKey(publicKey: Hex): Buffer {
  const sequence = new asn1.Sequence()
  const values = sequence.valueBlock.value
  for (const i of [0, 1]) {
    values.push(
      new asn1.Integer({
        value: i,
      }),
    )
  }
  const value = values[1] as asn1.BitString
  value.valueBlock.valueHexView = hexToBytes(publicKey)
  return Buffer.from(sequence.toBER(false))
}

const mockKmsClient = {
  getPublicKey: async ({ name: versionName }: { name: string }) => {
    const privateKey = MOCK_KEYS.get(versionName)
    if (!privateKey) {
      throw new Error(`Unable to locate key: '${versionName}'`)
    }

    const pubKey = secp256k1.getPublicKey(privateKey.slice(2), false)
    const derKey = derFromPublicKey(toHex(pubKey))
    const pem = `-----BEGIN PUBLIC KEY-----\n${derKey
      .toString('base64')
      .match(/.{0,64}/g)!
      .join('\n')}-----END PUBLIC KEY-----\n`
    return [{ pem }]
  },
  asymmetricSign: async ({
    name,
    digest,
  }: {
    name: string
    digest: { sha256: Buffer }
  }) => {
    const privateKey = MOCK_KEYS.get(name)
    if (!privateKey) {
      throw new Error(`Unable to locate key: ${name}`)
    }

    const signature = secp256k1.sign(digest.sha256, privateKey.slice(2))

    return [{ signature: signature.toDERRawBytes() }]
  },
} as unknown as KeyManagementServiceClient

describe('gcpHsmToAccount', () => {
  it('returns a valid viem account when given a known hsm key', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
      kmsClient: mockKmsClient,
    })
    expect(gcpHsmAccount).toEqual({
      address: ACCOUNT1.address,
      publicKey: ACCOUNT1.publicKey,
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
        kmsClient: mockKmsClient,
      }),
    ).rejects.toThrow("Unable to locate key: 'an-unknown-key'")
  })

  it('signs a message', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
      kmsClient: mockKmsClient,
    })

    const message = 'hello world'
    const signature = await gcpHsmAccount.signMessage({ message })

    expect(signature).toBe(
      '0x08c183d08a952dcd603148842de1d7844a1a6d72a3761840ebe10a570240821e3348c9296af823c8f4de5258f997fa35ee4ad8fce79cda929021f6976d0c10431c',
    )
    await expect(
      verifyMessage({
        address: ACCOUNT1.address,
        message,
        signature,
      }),
    ).resolves.toBeTruthy()
  })

  it('signs a transaction', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
      kmsClient: mockKmsClient,
    })
    const signedTx = await gcpHsmAccount.signTransaction({
      chainId: 1,
      maxFeePerGas: parseGwei('20'),
      gas: 21000n,
      to: ACCOUNT2.address,
      value: parseEther('1'),
    })

    expect(signedTx).toBe(
      '0x02f86f0180808504a817c80082520894588e4b68193001e4d10928660ab4165b813717c0880de0b6b3a764000080c080a045b0a758fd31e75c9f8558aa5eb2aee359693d781c2b2f8ef000d9bfefc8e3e7a004d6440b24582611c77b93113b5c6ac45d0ade91e8067ef8867a088e227be8d9',
    )
    await expect(
      recoverTransactionAddress({
        serializedTransaction: signedTx,
      }),
    ).resolves.toBe(ACCOUNT1.address)
  })

  it('signs typed data', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
      kmsClient: mockKmsClient,
    })
    const signature = await gcpHsmAccount.signTypedData(TYPED_DATA)
    expect(signature).toBe(
      '0x51a454925c2ff4cad0a09cc64fc970685a17f39b2c3a843323f0cc08942d413d15e1ee8c7ff2e12e85eaf1f887cadfbb20b270a579f0945f30de2a73cad4d8ce1c',
    )

    await expect(
      recoverTypedDataAddress({
        ...TYPED_DATA,
        signature,
      }),
    ).resolves.toBe(ACCOUNT1.address)
  })
})
