import { KeyManagementServiceClient } from '@google-cloud/kms'
import * as asn1 from 'asn1js'
import {
  LocalAccount,
  publicKeyToAddress,
  // privateKeyToAccount,
  toAccount,
} from 'viem/accounts'
// TODO remove if possible
// TODO remove if possible
import {
  GetTransactionType,
  Hex,
  SerializeTransactionFn,
  Signature,
  TransactionSerializable,
  TransactionSerialized,
  keccak256,
  serializeTransaction,
  toHex,
} from 'viem'
// TODO remove if possible
import BigNumber from 'bignumber.js'
import * as ethUtil from '@ethereumjs/util'
import { secp256k1 } from '@noble/curves/secp256k1'
import { SignatureType } from '@noble/curves/abstract/weierstrass'

export type GcpHsmAccount = LocalAccount<'gcpHsm'>

async function getPublicKey(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
): Promise<Hex> {
  const [pk] = await kmsClient.getPublicKey({ name: hsmKeyVersion })
  // if (
  //   pk.algorithm !==
  //   protos.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm
  //     .EC_SIGN_SECP256K1_SHA256
  // ) {
  //   throw new Error(`Unsupported algorithm: ${pk.algorithm}`)
  // }
  if (!pk.pem) {
    throw new Error('PublicKey pem is not defined')
  }
  const derEncodedPk = pemToDerEncode(pk.pem)
  return publicKeyFromAsn1(Buffer.from(derEncodedPk, 'base64'))
}

/**
 * Converts key from PEM to DER encoding.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding for X.509 certificates and private keys.
 * Unlike PEM, DER-encoded files do not contain plain text statements such as -----BEGIN CERTIFICATE-----
 *
 * https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#:~:text=DER%20(Distinguished%20Encoding%20Rules)%20is,commonly%20seen%20in%20Java%20contexts.
 */
function pemToDerEncode(pem: string): string {
  return pem.split('\n').slice(1, -2).join('').trim()
}

function publicKeyFromAsn1(b: Buffer): Hex {
  const { result } = asn1.fromBER(b)
  const values = (result as asn1.Sequence).valueBlock.value
  if (values.length < 2) {
    throw new Error('Cannot get public key from ASN.1: invalid sequence')
  }
  const value = values[1] as asn1.BitString
  return toHex(value.valueBlock.valueHexView)
}

///////

const toArrayBuffer = (b: Buffer): ArrayBuffer => {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)
}

/**
 * AWS returns DER encoded signatures but DER is valid BER
 */
export function parseBERSignature(b: Buffer): { r: Buffer; s: Buffer } {
  const { result } = asn1.fromBER(toArrayBuffer(b))

  const parts = (result as asn1.Sequence).valueBlock.value as asn1.BitString[]
  if (parts.length < 2) {
    throw new Error('Invalid signature parsed')
  }
  const [part1, part2] = parts

  return {
    r: Buffer.from(part1.valueBlock.valueHex),
    s: Buffer.from(part2.valueBlock.valueHex),
  }
}

type StrongAddress = `0x${string}`

const ensureLeading0x = (input: string): StrongAddress =>
  input.startsWith('0x') ? (input as StrongAddress) : (`0x${input}` as const)

const bufferToBigNumber = (input: Buffer): BigNumber => {
  return new BigNumber(ensureLeading0x(input.toString('hex')))
}

const bigNumberToBuffer = (input: BigNumber, lengthInBytes: number): Buffer => {
  let hex = input.toString(16)
  const hexLength = lengthInBytes * 2 // 2 hex characters per byte.
  if (hex.length < hexLength) {
    hex = '0'.repeat(hexLength - hex.length) + hex
  }
  return ethUtil.toBuffer(ensureLeading0x(hex)) as Buffer
}

/**
 * If the signature is in the "bottom" of the curve, it is non-canonical
 * Non-canonical signatures are illegal in Ethereum and therefore the S value
 * must be transposed to the lower intersection
 * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
 */
export const makeCanonical = (S: BigNumber): BigNumber => {
  const curveN = new BigNumber(secp256k1.CURVE.n.toString())
  const isCanonical = S.comparedTo(curveN.dividedBy(2)) <= 0
  if (!isCanonical) {
    return curveN.minus(S)
  }
  return S
}

const thirtyTwo: number = 32
const sixtyFour: number = 64

// class Signature {
//   public v: number
//   public r: Buffer
//   public s: Buffer

//   constructor(v: number, r: Buffer, s: Buffer) {
//     this.v = v
//     this.r = r
//     this.s = s
//   }
// }

/**
 * Attempts each recovery key to find a match
 */
export function recoverKeyIndex(
  signature: Uint8Array,
  _publicKey: BigNumber,
  hash: Uint8Array,
): number {
  const formats = ['fromCompact', 'fromDER'] as const

  for (let format of formats) {
    let sig: SignatureType
    try {
      sig = secp256k1.Signature[format](signature)
    } catch (e) {
      continue
    }

    for (let i = 0; i < 4; i++) {
      sig = sig.addRecoveryBit(i)
      const recoveredPublicKeyByteArr = sig.recoverPublicKey(hash)

      // NOTE:
      // converting hex value to bigint allows for discrepencies between
      // libraries to disappear, ran into an issue where
      // "0x01234" wasn't equal to "0x1234", the conversion removes it
      const compressedRecoveredPublicKey = BigInt(
        ensureLeading0x(recoveredPublicKeyByteArr.toHex(false)),
      )
      const uncompressedRecoveredPublicKey = BigInt(
        ensureLeading0x(recoveredPublicKeyByteArr.toHex(true)),
      )
      const publicKey = BigInt(ensureLeading0x(_publicKey.toString(16)))

      if (
        publicKey === compressedRecoveredPublicKey ||
        publicKey === uncompressedRecoveredPublicKey
      ) {
        return i
      }
    }
  }

  throw new Error('Unable to generate recovery key from signature.')
}

const trimLeading0x = (input: string) =>
  input.startsWith('0x') ? input.slice(2) : input

/////

async function findCanonicalSignature(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
  buffer: Buffer,
): Promise<{ S: BigNumber; R: BigNumber }> {
  const [signResponse] = await kmsClient.asymmetricSign({
    name: hsmKeyVersion,
    digest: {
      sha256: buffer,
    },
  })
  const { r, s } = parseBERSignature(signResponse.signature as Buffer)

  const R = bufferToBigNumber(r)
  let S = bufferToBigNumber(s)
  S = makeCanonical(S)

  return { S: S!, R: R! }
}

async function sign(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
  publicKey: BigNumber,
  buffer: Buffer,
): Promise<Signature> {
  const { R, S } = await findCanonicalSignature(
    kmsClient,
    hsmKeyVersion,
    buffer,
  )
  const rBuff = bigNumberToBuffer(R, thirtyTwo)
  const sBuff = bigNumberToBuffer(S, thirtyTwo)
  const recovery = recoverKeyIndex(
    Buffer.concat([rBuff, sBuff], sixtyFour),
    publicKey,
    buffer,
  )

  // old
  // return {
  //   r: rBuff,
  //   s: sBuff,
  //   v: recoveryParam,
  // }
  return {
    r: toHex(rBuff),
    s: toHex(sBuff),
    v: recovery ? BigInt(28) : BigInt(27),
    yParity: recovery,
  }
}

// async function signTransaction(addToV: number, encodedTx: RLPEncodedTx): Promise<Signature> {
//   const hash = getHashFromEncoded(encodedTx.rlpEncode)
//   const bufferedMessage = Buffer.from(trimLeading0x(hash), 'hex')
//   const { v, r, s } = await this.sign(bufferedMessage)

//   return {
//     v: v + addToV,
//     r,
//     s,
//   }
// }

type SignTransactionParameters<
  serializer extends
    SerializeTransactionFn<TransactionSerializable> = SerializeTransactionFn<TransactionSerializable>,
  transaction extends Parameters<serializer>[0] = Parameters<serializer>[0],
> = {
  kmsClient: KeyManagementServiceClient
  hsmKeyVersion: string
  publicKey: BigNumber
  transaction: transaction
  serializer?: serializer | undefined
}

type SignTransactionReturnType<
  serializer extends
    SerializeTransactionFn<TransactionSerializable> = SerializeTransactionFn<TransactionSerializable>,
  transaction extends Parameters<serializer>[0] = Parameters<serializer>[0],
> = TransactionSerialized<GetTransactionType<transaction>>

async function signTransaction<
  serializer extends
    SerializeTransactionFn<TransactionSerializable> = SerializeTransactionFn<TransactionSerializable>,
  transaction extends Parameters<serializer>[0] = Parameters<serializer>[0],
>(
  parameters: SignTransactionParameters<serializer, transaction>,
): Promise<SignTransactionReturnType<serializer, transaction>> {
  const {
    kmsClient,
    hsmKeyVersion,
    publicKey,
    transaction,
    serializer = serializeTransaction,
  } = parameters

  const signableTransaction = (() => {
    // For EIP-4844 Transactions, we want to sign the transaction payload body (tx_payload_body) without the sidecars (ie. without the network wrapper).
    // See: https://github.com/ethereum/EIPs/blob/e00f4daa66bd56e2dbd5f1d36d09fd613811a48b/EIPS/eip-4844.md#networking
    if (transaction.type === 'eip4844')
      return {
        ...transaction,
        sidecars: false,
      }
    return transaction
  })()

  const hash = keccak256(serializer(signableTransaction))

  // const signature = await sign({
  //   hash,
  //   privateKey,
  // })

  const signature = await sign(
    kmsClient,
    hsmKeyVersion,
    publicKey,
    Buffer.from(trimLeading0x(hash), 'hex'),
  )

  return serializer(transaction, signature) as SignTransactionReturnType<
    serializer,
    transaction
  >
}

/*async function signTransaction(addToV: number, encodedTx: RLPEncodedTx): Promise<Signature> {
  const hash = getHashFromEncoded(encodedTx.rlpEncode)
  const bufferedMessage = Buffer.from(trimLeading0x(hash), 'hex')
  const { v, r, s } = await this.sign(bufferedMessage)

  return {
    v: v + addToV,
    r,
    s,
  }
}

async function signPersonalMessage(data: string): Promise<Signature> {
  const dataBuff = ethUtil.toBuffer(ensureLeading0x(data))
  const msgHashBuff = ethUtil.hashPersonalMessage(dataBuff) as Buffer
  const { v, r, s } = await this.sign(msgHashBuff)

  return {
    v: v + 27,
    r,
    s,
  }
}

async function signTypedData(typedData: EIP712TypedData): Promise<Signature> {
  const typedDataHashBuff = generateTypedDataHash(typedData)
  const { v, r, s } = await this.sign(typedDataHashBuff)

  return {
    v: v + 27,
    r,
    s,
  }
}*/

export async function gcpHsmToAccount(
  hsmKeyVersion: string,
): Promise<GcpHsmAccount> {
  const kmsClient = new KeyManagementServiceClient()
  const publicKey = await getPublicKey(kmsClient, hsmKeyVersion)

  const publicKeyBigNumber = new BigNumber(publicKey)

  const address = publicKeyToAddress(publicKey)

  const account = toAccount({
    address,
    async signMessage({ message }) {
      throw new Error('Not implemented')
      // return signMessage({ message, privateKey })
    },
    async signTransaction(transaction, { serializer } = {}) {
      return signTransaction({
        kmsClient,
        hsmKeyVersion,
        publicKey: publicKeyBigNumber,
        transaction,
        serializer,
      })
    },
    async signTypedData(typedData) {
      throw new Error('Not implemented')
      // return signTypedData({ ...typedData, privateKey })
    },
  })

  return {
    ...account,
    publicKey,
    source: 'gcpHsm',
  }
}
