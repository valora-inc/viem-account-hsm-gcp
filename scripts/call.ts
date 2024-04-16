import { newKitFromWeb3, ContractKit } from '@celo/contractkit'
import { GcpHsmWallet } from '@celo/wallet-hsm-gcp'
import { gcpHsmToAccount } from '../src'
import {
  createWalletClient,
  formatUnits,
  http,
  parseEther,
  publicActions,
} from 'viem'
import { celoAlfajores } from 'viem/chains'
const Web3 = require('web3')

let contractKit: Promise<ContractKit> | null = null

async function getContractKit({
  rpcNodeUrl,
  hsmKeyVersion,
}: {
  rpcNodeUrl: string
  hsmKeyVersion: string
}): Promise<ContractKit> {
  if (contractKit) {
    return await contractKit
  }

  console.log('==here1')
  const httpProvider = new Web3.providers.HttpProvider(rpcNodeUrl)
  console.log('==here2')
  const web3 = new Web3(httpProvider)
  console.log('==here3')
  const gcpWallet = new GcpHsmWallet(hsmKeyVersion)
  console.log('==here4')
  await gcpWallet.init()
  console.log('==here5')
  const account = await gcpWallet.getAddressFromVersionName(hsmKeyVersion)
  console.log('==here6')
  const kit = newKitFromWeb3(web3, gcpWallet)
  kit.defaultAccount = account as any

  contractKit = Promise.resolve(kit)
  return await contractKit
}

;(async () => {
  const rpcNodeUrl = 'https://alfajores-forno.celo-testnet.org'
  const hsmKeyVersion =
    'projects/valora-viem-hsm-test/locations/global/keyRings/test/cryptoKeys/hsm/cryptoKeyVersions/1'
  // const kit = await getContractKit({ rpcNodeUrl, hsmKeyVersion })
  // console.log('ContractKit Account:', kit.defaultAccount)

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

  console.log('Hash:', hash)

  const receipt = await client.waitForTransactionReceipt({ hash })
  console.log('TX status:', receipt.status)

  if (receipt.status !== 'success') {
    throw new Error('Transaction failed!')
  }
})()
