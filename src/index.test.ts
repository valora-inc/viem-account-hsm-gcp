// import { CeloTx, EncodedTransaction } from '@celo/connect'
// import {
//   // ensureLeading0x,
//   // normalizeAddressWith0x,
//   // privateKeyToAddress,
//   // trimLeading0x,
// } from '@celo/utils/lib/address'
// import { verifySignature } from '@celo/utils/lib/signatureUtils'
// import {
//   recoverTransaction,
//   verifyEIP712TypedDataSigner,
// } from '@celo/wallet-base'
// import { asn1FromPublicKey } from '@celo/wallet-hsm'
import * as ethUtil from '@ethereumjs/util'
// import { BigNumber } from 'bignumber.js'
// NOTE: elliptic is disabled elsewhere in this library to prevent
// accidental signing of truncated messages.
// eslint-disable-next-line no-restricted-imports
// import { ec as EC } from 'elliptic'
// import Web3 from 'web3'

import { KeyManagementServiceClient } from '@google-cloud/kms'
import { secp256k1 } from '@noble/curves/secp256k1'
import { privateKeyToAccount } from 'viem/accounts'
import * as asn1 from 'asn1js'
import { GcpHsmAccount, gcpHsmToAccount } from './index'
import { Hex, hexToBytes, toHex } from 'viem'

// Note: A lot of this test class was copied from the wallet-hsm-aws test since they work very similarly.

export const PRIVATE_KEY1 =
  '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
export const ACCOUNT_ADDRESS1 = privateKeyToAccount(PRIVATE_KEY1).address
export const ACCOUNT_PUBLIC_KEY1 = privateKeyToAccount(PRIVATE_KEY1).publicKey
export const PRIVATE_KEY2 =
  '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890fdeccc'
export const ACCOUNT_ADDRESS2 = privateKeyToAccount(PRIVATE_KEY2).address

export const PRIVATE_KEY_NEVER =
  '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890ffffff'
export const ACCOUNT_ADDRESS_NEVER =
  privateKeyToAccount(PRIVATE_KEY_NEVER).address

export const CHAIN_ID = 44378

export const TYPED_DATA = {
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
    chainId: 1,
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
}

const MOCK_GCP_HSM_KEY_NAME =
  'projects/gcp-test-account/locations/global/keyRings/test/cryptoKeys/hsm/cryptoKeyVersions/1'

const key1 = PRIVATE_KEY1
// const ec = new EC('secp256k1')

const keys: Map<string, string> = new Map([[MOCK_GCP_HSM_KEY_NAME, key1]])

function asn1FromPublicKey(publicKey: Hex): Buffer {
  // const pkbuff = bigNumberToBuffer(bn, 64)
  const sequence = new asn1.Sequence()
  const values = sequence.valueBlock.value
  for (const i of [0, 1]) {
    values.push(
      new asn1.Integer({
        value: i,
      })
    )
  }
  const value = values[1] as asn1.BitString
  // Adding a dummy padding byte
  // const padding = Buffer.from(new Uint8Array([0x00]))
  value.valueBlock.valueHex = hexToBytes(publicKey) //Buffer.concat([padding, pkbuff])
  return Buffer.from(sequence.toBER(false))
}

const mockKmsClient = {
  getPublicKey: async ({ name: versionName }: { name: string }) => {
    const privateKey = keys.get(versionName)
    if (!privateKey) {
      throw new Error(`Unable to locate key: '${versionName}'`)
    }
    
    const ethUtilPubKey = ethUtil.privateToPublic(ethUtil.toBuffer(privateKey))
    console.log('==ethUtilPubKey', toHex(ethUtilPubKey))
    const pubKey = secp256k1.getPublicKey(privateKey.slice(2), false)
    console.log('==mypubKey', toHex(pubKey))
    // const temp = new BigNumber(toHex(pubKey))
    // const asn1Key = asn1FromPublicKey(temp)
    const asn1Key = asn1FromPublicKey(toHex(pubKey))
    const prefix = '-----BEGIN PUBLIC KEY-----\n'
    const postfix = '-----END PUBLIC KEY-----\n'
    const pem =
      prefix +
      asn1Key
        .toString('base64')
        .match(/.{0,64}/g)!
        .join('\n') +
      postfix
    return [{ pem }]
  },
  asymmetricSign: async ({
    name,
    digest,
  }: {
    name: string
    digest: { sha256: Buffer }
  }) => {
    const privateKey = keys.get(name)
    if (!privateKey) {
      throw new Error(`Unable to locate key: ${name}`)
    }

    // const pkBuffer = Buffer.from(privateKey, 'hex')
    // const signature = ec.sign(digest.sha256, pkBuffer, { canonical: true })
    // return [{ signature: Buffer.from(signature.toDER()) }]
    const signature = secp256k1.sign(digest.sha256, privateKey.slice(2))
    const signatureWithoutRecovery = new secp256k1.Signature(
      signature.r,
      signature.s,
    )
    console.log('==signature', signature, signature.toDERHex())
    console.log(
      '==signatureWithoutRecovery',
      signatureWithoutRecovery,
      signatureWithoutRecovery.toDERHex(),
    )
    console.log(
      '==equal',
      signature.toDERHex() === signatureWithoutRecovery.toDERHex(),
    )

    console.log('===ACCOUNT_PUBLIC_KEY1', ACCOUNT_PUBLIC_KEY1)
    console.log(
      '==recoveredPublicKey',
      signature.recoverPublicKey(digest.sha256).toHex(false),
    )

    return [
      { signature: Buffer.from(signatureWithoutRecovery.toDERRawBytes()) },
    ]
  },
} as unknown as KeyManagementServiceClient

describe('gcpHsmToAccount', () => {
  // let gcpHsmAccount: GcpHsmAccount
  // // let knownAddress: string
  // // const otherAddress: string = ACCOUNT_ADDRESS2

  // beforeEach(async () => {
  //   gcpHsmAccount = await gcpHsmToAccount({
  //     hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
  //     kmsClient: mockKmsClient,
  //   })
  // })

  it('returns a valid viem account when given a known hsm key', async () => {
    const gcpHsmAccount = await gcpHsmToAccount({
      hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
      kmsClient: mockKmsClient,
    })
    expect(gcpHsmAccount.address).toBe(ACCOUNT_ADDRESS1)
    expect(gcpHsmAccount.type).toBe('local')
    expect(gcpHsmAccount.source).toBe('gcpHsm')
  })

  it('throws an error when given an unknown hsm key', async () => {
    await expect(
      gcpHsmToAccount({
        hsmKeyVersion: 'an-unknown-key',
        kmsClient: mockKmsClient,
      }),
    ).rejects.toThrow("Unable to locate key: 'an-unknown-key'")
  })

  describe('with a valid hsm account', () => {
    let gcpHsmAccount: GcpHsmAccount

    beforeEach(async () => {
      gcpHsmAccount = await gcpHsmToAccount({
        hsmKeyVersion: MOCK_GCP_HSM_KEY_NAME,
        kmsClient: mockKmsClient,
      })
    })

    describe('signMessage', () => {
      it('succeeds', async () => {
        const message = 'hello world'
        const signature = await gcpHsmAccount.signMessage({ message })
        expect(signature).not.toBeUndefined()
      })
    })
  })

  // test('hasAccount should return false for keys that are not present', async () => {
  //   expect(
  //     await gcpHsmAccount.hasAccount('this is not a valid private key'),
  //   ).toBeFalsy()
  // })

  // test('hasAccount should return true for keys that are present', async () => {
  //   // Valid key should be present
  //   const address =
  //     await gcpHsmAccount.getAddressFromVersionName(MOCK_GCP_HSM_KEY_NAME)
  //   expect(await gcpHsmAccount.hasAccount(address)).toBeTruthy()
  // })

  // test('throws on invalid key id', async () => {
  //   try {
  //     await gcpHsmAccount.getAddressFromVersionName('invalid')
  //     throw new Error('expected error to have been thrown')
  //   } catch (e: any) {
  //     expect(e.message).toContain(
  //       "3 INVALID_ARGUMENT: Resource name 'invalid' does not match pattern",
  //     )
  //   }
  // })

  /*describe('signing', () => {
    let celoTransaction: CeloTx
    // const unknownKey: string = '00000000-0000-0000-0000-000000000000'
    // const unknownAddress = ACCOUNT_ADDRESS_NEVER

    describe('using a known key', () => {
      const knownKey: string = MOCK_GCP_HSM_KEY_NAME!
      beforeEach(async () => {
        // knownAddress = await gcpHsmAccount.getAddressFromVersionName(knownKey)
        celoTransaction = {
          from: knownAddress,
          to: otherAddress,
          chainId: CHAIN_ID,
          value: Web3.utils.toWei('1', 'ether'),
          nonce: 0,
          gas: '10',
          gasPrice: '99',
          feeCurrency: '0x',
          gatewayFeeRecipient: ACCOUNT_ADDRESS_NEVER,
          gatewayFee: '0x5678',
          data: '0xabcdef',
        }
      })

      describe('when calling signTransaction', () => {
        test('succeeds', async () => {
          const signedTx: EncodedTransaction =
            await gcpHsmAccount.signTransaction(celoTransaction)
          expect(signedTx).not.toBeUndefined()
        })
        test('with same signer', async () => {
          const signedTx: EncodedTransaction =
            await gcpHsmAccount.signTransaction(celoTransaction)
          const [, recoveredSigner] = recoverTransaction(signedTx.raw)
          expect(normalizeAddressWith0x(recoveredSigner)).toBe(
            normalizeAddressWith0x(knownAddress),
          )
        })
        // https://github.com/ethereum/go-ethereum/blob/38aab0aa831594f31d02c9f02bfacc0bef48405d/rlp/decode.go#L664
        test('signature with 0x00 prefix is canonicalized', async () => {
          // This tx is carefully constructed to produce an S value with the first byte as 0x00
          const celoTransactionZeroPrefix = {
            from: await gcpHsmAccount.getAddressFromVersionName(knownKey),
            to: ACCOUNT_ADDRESS2,
            chainId: CHAIN_ID,
            value: Web3.utils.toWei('1', 'ether'),
            nonce: 65,
            gas: '10',
            gasPrice: '99',
            feeCurrency: '0x',
            gatewayFeeRecipient: ACCOUNT_ADDRESS_NEVER,
            gatewayFee: '0x5678',
            data: '0xabcdef',
          }
          const signedTx: EncodedTransaction =
            await gcpHsmAccount.signTransaction(celoTransactionZeroPrefix)
          expect(signedTx.tx.s.startsWith('0x00')).toBeFalsy()
          const [, recoveredSigner] = recoverTransaction(signedTx.raw)
          expect(normalizeAddressWith0x(recoveredSigner)).toBe(
            normalizeAddressWith0x(knownAddress),
          )
        })
      })

      describe('when calling signPersonalMessage', () => {
        test('succeeds', async () => {
          const hexStr: string = ACCOUNT_ADDRESS1
          const signedMessage = await gcpHsmAccount.signPersonalMessage(
            knownAddress,
            hexStr,
          )
          expect(signedMessage).not.toBeUndefined()
          const valid = verifySignature(hexStr, signedMessage, knownAddress)
          expect(valid).toBeTruthy()
        })
      })

      describe('when calling signTypedData', () => {
        test('succeeds', async () => {
          const signedMessage = await gcpHsmAccount.signTypedData(TYPED_DATA)
          expect(signedMessage).not.toBeUndefined()
          const valid = verifyEIP712TypedDataSigner(
            TYPED_DATA,
            signedMessage,
            knownAddress,
          )
          expect(valid).toBeTruthy()
        })
      })
    })
  })*/
})
