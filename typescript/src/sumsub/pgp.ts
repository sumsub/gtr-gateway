import type * as OpenPgp from 'openpgp'

import { CryptoError, GatewayConfigurationError } from '../errors.js'
import { DEFAULT_TIMESTAMP_TOLERANCE_SECONDS } from './signature.js'

export const ENCRYPTION_HEADER = 'x-encryption'
export const ENCRYPTION_HEADER_VALUE = 'true'

const MAX_PLAINTEXT_BYTES = 1024 * 1024
const ARMORED_BLOCK = /-----BEGIN PGP [A-Z ]+-----[\s\S]*?-----END PGP [A-Z ]+-----/g

export interface PgpDecryptorOptions {
  /** One or more ASCII-armored gateway private keys; during a rotation add the new key after the old one. */
  readonly privateKeys: string
  /** Unlocks every encrypted private key. */
  readonly passphrase?: string
  /** The ASCII-armored Sumsub public key shown in the dashboard card. */
  readonly sumsubPublicKey: string
  readonly toleranceSeconds?: number
  readonly now?: () => Date
}

export interface PgpDecryptor {
  /** Decrypts an armored message and checks that Sumsub signed it recently; rejects anything else. */
  decrypt(armoredMessage: Uint8Array | string): Promise<Buffer>
}

/** Accepts keys pasted into an environment variable as a single line with literal `\\n` sequences. */
export function normalizeArmored(value: string): string {
  return value.includes('\n') ? value : value.replaceAll('\\n', '\n')
}

/** Needs the optional `openpgp` dependency: `npm install openpgp`. */
export async function createPgpDecryptor(options: PgpDecryptorOptions): Promise<PgpDecryptor> {
  const openpgp = await loadOpenPgp()
  const privateKeys: OpenPgp.PrivateKey[] = []
  for (const block of armoredBlocks(options.privateKeys, 'gateway PGP private key')) {
    const key = await openpgp.readPrivateKey({ armoredKey: block })
    privateKeys.push(
      key.isDecrypted()
        ? key
        : await openpgp.decryptKey({ privateKey: key, passphrase: options.passphrase ?? '' }),
    )
  }
  const sumsubPublicKey = await openpgp.readKey({
    armoredKey: armoredBlocks(options.sumsubPublicKey, 'Sumsub PGP public key')[0] ?? '',
  })
  const toleranceMs = (options.toleranceSeconds ?? DEFAULT_TIMESTAMP_TOLERANCE_SECONDS) * 1000
  const now = options.now ?? (() => new Date())

  return {
    async decrypt(armoredMessage) {
      let result: OpenPgp.DecryptMessageResult & { data: Uint8Array }
      try {
        const message = await openpgp.readMessage({
          armoredMessage: Buffer.from(armoredMessage).toString('utf8'),
        })
        result = await openpgp.decrypt({
          message,
          decryptionKeys: privateKeys,
          verificationKeys: sumsubPublicKey,
          expectSigned: true,
          format: 'binary',
          config: { maxDecompressedMessageSize: MAX_PLAINTEXT_BYTES },
        })
      } catch (error) {
        if (error instanceof Error && error.message.includes('decompressed')) {
          throw new CryptoError('Request body is too large', { cause: error })
        }
        throw new CryptoError('Request body cannot be decrypted or is not signed by Sumsub', {
          cause: error,
        })
      }
      const signature = await result.signatures[0]?.signature
      const created = signature?.packets[0]?.created
      if (!created) {
        throw new CryptoError('Request signature is invalid')
      }
      if (Math.abs(now().getTime() - created.getTime()) > toleranceMs) {
        throw new CryptoError(
          'Request signature is outside the allowed time window; check the gateway clock',
        )
      }
      return Buffer.from(result.data)
    },
  }
}

async function loadOpenPgp(): Promise<typeof OpenPgp> {
  try {
    return await import('openpgp')
  } catch (error) {
    throw new GatewayConfigurationError(
      'Payload encryption needs the optional dependency openpgp: npm install openpgp',
      { cause: error },
    )
  }
}

function armoredBlocks(value: string, name: string): string[] {
  const blocks = normalizeArmored(value).match(ARMORED_BLOCK) ?? []
  if (blocks.length === 0) {
    throw new GatewayConfigurationError(`The ${name} is not ASCII-armored`)
  }
  return blocks
}
