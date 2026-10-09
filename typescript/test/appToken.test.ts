import { describe, expect, it } from 'vitest'

import { computeAppTokenSignature, signedSumsubHeaders } from '../src/sumsub/appToken.js'

const SECRET = 'test-secret'
const TS = '1756368000'
const PATH = '/resources/api/tr/gtrGateway/callback'
const BODY = '{"callbackType":0,"requestId":"cb-1"}'
const EXPECTED = '3f47251e6ae794e29899e421020c4c2dd676afed1dfaf2948fc5db2552fe3d81'

describe('Sumsub app token signature', () => {
  it('reproduces the reference signature', () => {
    expect(computeAppTokenSignature(SECRET, TS, 'POST', PATH, BODY)).toBe(EXPECTED)
  })

  it('upper-cases the method and builds the three headers', () => {
    const headers = signedSumsubHeaders(
      { appToken: 'tok', appSecret: SECRET },
      'post',
      PATH,
      BODY,
      new Date(Number(TS) * 1000),
    )
    expect(headers).toEqual({
      'X-App-Token': 'tok',
      'X-App-Access-Ts': TS,
      'X-App-Access-Sig': EXPECTED,
    })
  })

  it('changes with every signed component', () => {
    expect(computeAppTokenSignature(SECRET, '1756368001', 'POST', PATH, BODY)).not.toBe(EXPECTED)
    expect(computeAppTokenSignature(SECRET, TS, 'GET', PATH, BODY)).not.toBe(EXPECTED)
    expect(computeAppTokenSignature(SECRET, TS, 'POST', PATH + '?x=1', BODY)).not.toBe(EXPECTED)
    expect(computeAppTokenSignature(SECRET, TS, 'POST', PATH, '{}')).not.toBe(EXPECTED)
  })
})
