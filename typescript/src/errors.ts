export class GatewayError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options)
    this.name = new.target.name
  }
}

export class InvalidSignatureError extends GatewayError {
  constructor(message = 'Request signature is missing or invalid') {
    super(401, 'invalid_signature', message)
  }
}

export class InvalidRequestError extends GatewayError {
  constructor(message: string, options?: ErrorOptions) {
    super(400, 'invalid_request', message, options)
  }
}

export class PayloadTooLargeError extends GatewayError {
  constructor() {
    super(413, 'invalid_request', 'Request body is too large')
  }
}

export class CryptoError extends GatewayError {
  constructor(message: string, options?: ErrorOptions) {
    super(422, 'crypto_failed', message, options)
  }
}

export class GtrUnreachableError extends GatewayError {
  constructor(cause: unknown) {
    super(502, 'gtr_unreachable', 'GTR API is unreachable', { cause })
  }
}

export class GtrLoginError extends GatewayError {
  constructor(message: string) {
    super(502, 'gtr_login_failed', message)
  }
}

export class SumsubUnreachableError extends GatewayError {
  constructor(cause: unknown) {
    super(502, 'sumsub_unreachable', 'Sumsub API is unreachable', { cause })
  }
}

/** Thrown at start-up when the gateway options cannot work, for example an empty secret key. */
export class GatewayConfigurationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'GatewayConfigurationError'
  }
}
