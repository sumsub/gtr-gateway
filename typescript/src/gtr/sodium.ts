import { createRequire } from 'node:module'

import type * as Sodium from 'libsodium-wrappers'

// The ESM build of libsodium-wrappers 0.7.x imports a file that is not published
// (`./libsodium.mjs`), so the CommonJS build is loaded explicitly.
const require = createRequire(import.meta.url)

export const sodium = require('libsodium-wrappers') as typeof Sodium
