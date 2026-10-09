import { readFileSync } from 'node:fs'

import { z } from 'zod'

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace'] as const

const optionalText = z.preprocess(
  (value) => (value === '' ? undefined : value),
  z.string().min(1).optional(),
)

const configSchema = z
  .object({
    HOST: z.string().default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),

    SUMSUB_SECRET_KEY: z.string().min(1),
    SUMSUB_SECRET_KEY_PREVIOUS: optionalText,
    SUMSUB_API_URL: z.string().url().default('https://api.sumsub.com'),
    SUMSUB_APP_TOKEN: optionalText,
    SUMSUB_APP_SECRET: optionalText,

    GTR_API_URL: z.string().url(),
    GTR_VASP_CODE: z.string().min(1),
    GTR_ACCESS_KEY: z.string().min(1),
    GTR_SECRET_KEY: z.string().min(1),
    GTR_CLIENT_CERT_PATH: z.string().min(1),
    GTR_CLIENT_CERT_PASSWORD: z.string().default(''),
    GTR_CA_CERT_PATH: optionalText,
    GTR_PRIVATE_KEY: z.string().min(1),

    GATEWAY_PGP_PRIVATE_KEY: optionalText,
    GATEWAY_PGP_PRIVATE_KEY_PASSPHRASE: optionalText,
    SUMSUB_PGP_PUBLIC_KEY: optionalText,
  })
  .refine((env) => (env.SUMSUB_APP_TOKEN === undefined) === (env.SUMSUB_APP_SECRET === undefined), {
    message: 'SUMSUB_APP_TOKEN and SUMSUB_APP_SECRET must be set together',
    path: ['SUMSUB_APP_TOKEN'],
  })
  .refine(
    (env) =>
      (env.GATEWAY_PGP_PRIVATE_KEY === undefined) === (env.SUMSUB_PGP_PUBLIC_KEY === undefined),
    {
      message: 'GATEWAY_PGP_PRIVATE_KEY and SUMSUB_PGP_PUBLIC_KEY must be set together',
      path: ['GATEWAY_PGP_PRIVATE_KEY'],
    },
  )

export type Config = z.infer<typeof configSchema>

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConfigurationError'
  }
}

/** Every variable can instead be read from a file: NAME_FILE holds the path, as with Docker and Kubernetes secrets. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = []
  const resolved: Record<string, string | undefined> = {}
  for (const [name, value] of Object.entries(env)) {
    if (!name.endsWith('_FILE')) {
      resolved[name] = value
    }
  }
  for (const [name, path] of Object.entries(env)) {
    if (!name.endsWith('_FILE') || !path) {
      continue
    }
    const target = name.slice(0, -'_FILE'.length)
    if (env[target]) {
      problems.push(`  ${target} and ${name}: set only one of them`)
      continue
    }
    try {
      resolved[target] = readFileSync(path, 'utf8').replace(/[\r\n]+$/, '')
    } catch (error) {
      problems.push(`  ${name}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  const parsed = configSchema.safeParse(resolved)
  if (!parsed.success) {
    problems.push(
      ...parsed.error.issues.map((issue) => `  ${issue.path.join('.')}: ${issue.message}`),
    )
  }
  if (problems.length > 0 || !parsed.success) {
    throw new ConfigurationError(`Invalid configuration:\n${problems.join('\n')}`)
  }
  return parsed.data
}
