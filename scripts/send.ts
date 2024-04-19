/* eslint-disable no-console */
import { gcpHsmToAccount } from '../src'
import {
  createWalletClient,
  formatUnits,
  http,
  parseEther,
  publicActions,
} from 'viem'
import { celoAlfajores } from 'viem/chains'

async function main() {
  const hsmKeyVersion =
    'projects/valora-viem-hsm-test/locations/global/keyRings/test/cryptoKeys/hsm/cryptoKeyVersions/1'

  const viemHsmAccount = await gcpHsmToAccount({ hsmKeyVersion })
  const { address } = viemHsmAccount
  console.log('Viem HSM Account:', address)

  const client = createWalletClient({
    account: viemHsmAccount,
    chain: celoAlfajores,
    transport: http(),
  }).extend(publicActions)

  const balance = await client.getBalance({ address })
  console.log(`Balance: ${formatUnits(balance, 18)} CELO`)

  console.log('Sending 0.001 CELO from Viem HSM Account...')
  const hash = await client.sendTransaction({
    to: viemHsmAccount.address,
    value: parseEther('0.001'),
  })

  console.log('Waiting for transaction hash:', hash)

  const receipt = await client.waitForTransactionReceipt({ hash })
  console.log('TX status:', receipt.status)

  if (receipt.status !== 'success') {
    throw new Error('Transaction failed!')
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
