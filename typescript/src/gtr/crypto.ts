import { CryptoError } from '../errors.js'
import { sodium } from './sodium.js'

export interface Ed25519KeyPair {
  readonly publicKey: Uint8Array
  readonly privateKey: Uint8Array
}

let ready = false

/** libsodium loads asynchronously; call once before any other function in this module. */
export async function initCrypto(): Promise<void> {
  await sodium.ready
  ready = true
}

function assertReady(): void {
  if (!ready) {
    throw new Error('Call and await initCrypto() before using the GTR crypto functions')
  }
}

/**
 * Parses a base64 Ed25519 private key in either format found in GTR credentials:
 * the 32-byte seed, or the 64-byte libsodium secret key (seed followed by public key).
 */
export function parseEd25519PrivateKey(base64: string): Ed25519KeyPair {
  assertReady()
  const bytes = fromBase64(base64)
  if (bytes.length === sodium.crypto_sign_SEEDBYTES) {
    const keyPair = sodium.crypto_sign_seed_keypair(bytes)
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey }
  }
  if (bytes.length === sodium.crypto_sign_SECRETKEYBYTES) {
    return { publicKey: bytes.slice(sodium.crypto_sign_SEEDBYTES), privateKey: bytes }
  }
  throw new CryptoError(
    `Ed25519 private key must be ${sodium.crypto_sign_SEEDBYTES} or ${sodium.crypto_sign_SECRETKEYBYTES} bytes, got ${bytes.length}`,
  )
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  assertReady()
  const generated = sodium.crypto_sign_keypair()
  return { publicKey: generated.publicKey, privateKey: generated.privateKey }
}

export function parseEd25519PublicKey(base64: string): Uint8Array {
  assertReady()
  const bytes = fromBase64(base64)
  if (bytes.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new CryptoError(
      `Ed25519 public key must be ${sodium.crypto_sign_PUBLICKEYBYTES} bytes, got ${bytes.length}`,
    )
  }
  return bytes
}

/**
 * GTR PII envelope: NaCl crypto_box between the two VASPs' Ed25519 identities converted to X25519.
 * Returns base64(nonce[24] || mac[16] || ciphertext).
 */
export function encryptPayload(
  plaintext: string,
  ownKeyPair: Ed25519KeyPair,
  counterpartyPublicKey: Uint8Array,
): string {
  assertReady()
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const box = sodium.crypto_box_easy(
    sodium.from_string(plaintext),
    nonce,
    toCurvePublicKey(counterpartyPublicKey),
    toCurvePrivateKey(ownKeyPair),
  )
  return toBase64(concat(nonce, box))
}

export function decryptPayload(
  packetBase64: string,
  ownKeyPair: Ed25519KeyPair,
  counterpartyPublicKey: Uint8Array,
): string {
  assertReady()
  const packet = fromBase64(packetBase64)
  if (packet.length < sodium.crypto_box_NONCEBYTES + sodium.crypto_box_MACBYTES) {
    throw new CryptoError('Encrypted payload is too short')
  }
  const nonce = packet.slice(0, sodium.crypto_box_NONCEBYTES)
  const box = packet.slice(sodium.crypto_box_NONCEBYTES)
  try {
    return sodium.to_string(
      sodium.crypto_box_open_easy(
        box,
        nonce,
        toCurvePublicKey(counterpartyPublicKey),
        toCurvePrivateKey(ownKeyPair),
      ),
    )
  } catch (error) {
    throw new CryptoError('Encrypted payload cannot be decrypted', { cause: error })
  }
}

export function signPayload(data: Uint8Array, ownKeyPair: Ed25519KeyPair): string {
  assertReady()
  return toBase64(sodium.crypto_sign_detached(data, ownKeyPair.privateKey))
}

export function verifyPayloadSignature(
  signatureBase64: string,
  data: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  assertReady()
  try {
    return sodium.crypto_sign_verify_detached(fromBase64(signatureBase64), data, publicKey)
  } catch {
    return false
  }
}

export function toBase64(bytes: Uint8Array): string {
  assertReady()
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}

export function fromBase64(value: string): Uint8Array {
  assertReady()
  try {
    return sodium.from_base64(value, sodium.base64_variants.ORIGINAL)
  } catch (error) {
    throw new CryptoError('Value is not valid base64', { cause: error })
  }
}

function toCurvePrivateKey(keyPair: Ed25519KeyPair): Uint8Array {
  return sodium.crypto_sign_ed25519_sk_to_curve25519(keyPair.privateKey)
}

function toCurvePublicKey(publicKey: Uint8Array): Uint8Array {
  try {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey)
  } catch (error) {
    throw new CryptoError('Counterparty public key is not a valid Ed25519 key', { cause: error })
  }
}

function concat(first: Uint8Array, second: Uint8Array): Uint8Array {
  const result = new Uint8Array(first.length + second.length)
  result.set(first)
  result.set(second, first.length)
  return result
}
