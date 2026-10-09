export interface GtrResponse {
  readonly status: number
  readonly body: unknown
}

export interface GtrCommonResponse<T = unknown> {
  success?: boolean
  verifyStatus?: number
  verifyMessage?: string
  data?: T
}

export interface GtrLoginResponse {
  success?: boolean
  status?: string
  msg?: string
  data?: {
    jwt?: string
    vaspCode?: string
  }
}

export interface GtrOneStepRequest {
  [field: string]: unknown
  targetVaspPublicKey: string
  encryptedPayload?: string
  initiatorPublicKey?: string
}

export interface SumsubOneStepRequest {
  [field: string]: unknown
  targetVaspPublicKey: string
  payload: Record<string, unknown>
}

export interface GtrApi {
  vaspDetail(vaspCode: string): Promise<GtrResponse>
  autoAddressVaspDetection(body: unknown): Promise<GtrResponse>
  oneStep(body: GtrOneStepRequest): Promise<GtrResponse>
  submitTxId(body: unknown): Promise<GtrResponse>
  endTravelRule(body: unknown): Promise<GtrResponse>
}
