import { KeyManagementServiceClient } from '@google-cloud/kms'
import * as asn1 from 'asn1js'
import { LocalAccount, publicKeyToAddress, toAccount } from 'viem/accounts'
import {
  GetTransactionType,
  Hex,
  SerializeTransactionFn,
  SignableMessage,
  Signature,
  TransactionSerializable,
  TransactionSerialized,
  TypedData,
  TypedDataDefinition,
  hashMessage,
  hashTypedData,
  hexToBigInt,
  hexToBytes,
  keccak256,
  serializeTransaction,
  signatureToHex,
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

type SignMessageParameters = {
  message: SignableMessage
  kmsClient: KeyManagementServiceClient
  hsmKeyVersion: string
  publicKey: Hex
}

async function signMessage({
  message,
  kmsClient,
  hsmKeyVersion,
  publicKey,
}: SignMessageParameters): Promise<Hex> {
  const signature = await sign(
    kmsClient,
    hsmKeyVersion,
    publicKey,
    hashMessage(message),
  )
  return signatureToHex(signature)
}

type SignTypedDataParameters<
  typedData extends TypedData | Record<string, unknown> = TypedData,
  primaryType extends keyof typedData | 'EIP712Domain' = keyof typedData,
> = TypedDataDefinition<typedData, primaryType> & {
  kmsClient: KeyManagementServiceClient
  hsmKeyVersion: string
  publicKey: Hex
}

async function signTypedData<
  const typedData extends TypedData | Record<string, unknown>,
  primaryType extends keyof typedData | 'EIP712Domain',
>(parameters: SignTypedDataParameters<typedData, primaryType>): Promise<Hex> {
  const { kmsClient, hsmKeyVersion, publicKey, ...typedData } =
    parameters as unknown as SignTypedDataParameters
  const signature = await sign(
    kmsClient,
    hsmKeyVersion,
    publicKey,
    hashTypedData(typedData),
  )
  return signatureToHex(signature)
}

export async function gcpHsmToAccount({
  hsmKeyVersion,
  kmsClient: kmsClient_,
}: {
  hsmKeyVersion: string
  kmsClient?: KeyManagementServiceClient
}): Promise<GcpHsmAccount> {
  const kmsClient = kmsClient_ ?? new KeyManagementServiceClient()
  const publicKey = await getPublicKey(kmsClient, hsmKeyVersion)
  const address = publicKeyToAddress(publicKey)

  const account = toAccount({
    address,
    async signMessage({ message }) {
      return signMessage({ message, kmsClient, hsmKeyVersion, publicKey })
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
      return signTypedData({
        ...typedData,
        kmsClient,
        hsmKeyVersion,
        publicKey,
      })
    },
  })

  return {
    ...account,
    publicKey,
    source: 'gcpHsm',
  }
}
