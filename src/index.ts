import { KeyManagementServiceClient } from '@google-cloud/kms'
import * as asn1 from 'asn1js'
import { LocalAccount, publicKeyToAddress, toAccount } from 'viem/accounts'
import {
  Hex,
  Signature,
  hashMessage,
  hashTypedData,
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

// Including 0x prefix
const UNCOMPRESSED_PUBLIC_KEY_HEX_LENGTH = 132 // 2 * 66

async function getPublicKey(
  kmsClient: KeyManagementServiceClient,
  hsmKeyVersion: string,
): Promise<Hex> {
  const [pk] = await kmsClient.getPublicKey({ name: hsmKeyVersion })
  if (!pk.pem) {
    throw new Error('PublicKey pem is not defined')
  }
  const derEncodedPk = pemToDer(pk.pem)
  return publicKeyFromDer(derEncodedPk)
}

/**
 * Converts key from PEM to DER encoding.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding for X.509 certificates and private keys.
 * Unlike PEM, DER-encoded files do not contain plain text statements such as -----BEGIN CERTIFICATE-----
 *
 * https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#:~:text=DER%20(Distinguished%20Encoding%20Rules)%20is,commonly%20seen%20in%20Java%20contexts.
 */
function pemToDer(pem: string): Uint8Array {
  const base64 = pem.split('\n').slice(1, -2).join('').trim()
  return Buffer.from(base64, 'base64')
}

function publicKeyFromDer(bytes: Uint8Array): Hex {
  // DER is a subset of BER (Basic Encoding Rules)
  const { result } = asn1.fromBER(bytes)
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
  for (let i = 0; i < 4; i++) {
    const recoveredSig = signature.addRecoveryBit(i)
    const compressed = publicKey.length < UNCOMPRESSED_PUBLIC_KEY_HEX_LENGTH
    const recoveredPublicKey = `0x${recoveredSig.recoverPublicKey(hash).toHex(compressed)}`
    if (publicKey === recoveredPublicKey) {
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
    v: BigInt(recovery) + 27n,
    yParity: recovery,
  }
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
      const signature = await sign(
        kmsClient,
        hsmKeyVersion,
        publicKey,
        hashMessage(message),
      )
      return signatureToHex(signature)
    },
    async signTransaction(
      transaction,
      { serializer = serializeTransaction } = {},
    ) {
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

      return serializer(transaction, signature)
    },
    async signTypedData(typedData) {
      const signature = await sign(
        kmsClient,
        hsmKeyVersion,
        publicKey,
        hashTypedData(typedData),
      )
      return signatureToHex(signature)
    },
  })

  return {
    ...account,
    publicKey,
    source: 'gcpHsm',
  }
}
