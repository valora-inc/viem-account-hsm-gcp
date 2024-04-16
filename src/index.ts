import { KeyManagementServiceClient } from '@google-cloud/kms'
import * as asn1 from 'asn1js'
import { LocalAccount, publicKeyToAddress, toAccount } from 'viem/accounts'
import {
  GetTransactionType,
  Hex,
  SerializeTransactionFn,
  Signature,
  TransactionSerializable,
  TransactionSerialized,
  hexToBigInt,
  hexToBytes,
  keccak256,
  serializeTransaction,
  toHex,
} from 'viem'
import { secp256k1 } from '@noble/curves/secp256k1'
import {
  RecoveredSignatureType,
  SignatureType,
} from '@noble/curves/abstract/weierstrass'

export type GcpHsmAccount = LocalAccount<'gcpHsm'>

async function getPublicKey(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
): Promise<Hex> {
  const [pk] = await kmsClient.getPublicKey({ name: hsmKeyVersion })
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

async function signWithKms(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
  hash: Uint8Array,
): Promise<SignatureType> {
  const [signResponse] = await kmsClient.asymmetricSign({
    name: hsmKeyVersion,
    digest: {
      sha256: hash,
    },
  })

  // Return normalized signature
  // > All transaction signatures whose s-value is greater than secp256k1n/2 are now considered invalid.
  // See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
  return secp256k1.Signature.fromDER(
    signResponse.signature as Buffer,
  ).normalizeS()
}

/**
 * Attempts each recovery key to find a match
 */
async function getRecoveredSignature(
  signature: SignatureType,
  publicKey: Hex,
  hash: Uint8Array,
): Promise<RecoveredSignatureType> {
  const publicKeyBigInt = hexToBigInt(publicKey)

  for (let i = 0; i < 4; i++) {
    const recoveredSig = signature.addRecoveryBit(i)
    const recoveredPublicKey = recoveredSig.recoverPublicKey(hash)

    // NOTE:
    // converting hex value to bigint allows for discrepancies between
    // libraries to disappear, ran into an issue where
    // "0x01234" wasn't equal to "0x1234", the conversion removes it
    const compressedRecoveredPublicKey = hexToBigInt(
      `0x${recoveredPublicKey.toHex(false)}`,
    )
    const uncompressedRecoveredPublicKey = hexToBigInt(
      `0x${recoveredPublicKey.toHex(true)}`,
    )

    if (
      publicKeyBigInt === compressedRecoveredPublicKey ||
      publicKeyBigInt === uncompressedRecoveredPublicKey
    ) {
      return recoveredSig
    }
  }

  throw new Error('Unable to generate recovery key from signature.')
}

async function sign(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
  publicKey: Hex,
  msgHash: Hex,
): Promise<Signature> {
  const hash = hexToBytes(msgHash)
  const signature = await signWithKms(kmsClient, hsmKeyVersion, hash)
  const { r, s, recovery } = await getRecoveredSignature(
    signature,
    publicKey,
    hash,
  )
  console.log('==recovery', recovery)
  return {
    r: toHex(r),
    s: toHex(s),
    v: BigInt(recovery + 27),
    yParity: recovery,
  }
}

type SignTransactionParameters<
  serializer extends
    SerializeTransactionFn<TransactionSerializable> = SerializeTransactionFn<TransactionSerializable>,
  transaction extends Parameters<serializer>[0] = Parameters<serializer>[0],
> = {
  kmsClient: KeyManagementServiceClient
  hsmKeyVersion: string
  publicKey: Hex
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
  const signature = await sign(kmsClient, hsmKeyVersion, publicKey, hash)

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
        publicKey,
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
