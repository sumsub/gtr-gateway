const MAX_RESPONSE_BYTES = 10 * 1024 * 1024

/** Reads a response body up to a size limit and parses it as JSON, or returns the text when it is not JSON. */
export async function readJsonOrText(body: AsyncIterable<Uint8Array>): Promise<unknown> {
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of body) {
    size += chunk.length
    if (size > MAX_RESPONSE_BYTES) {
      throw new Error('Response body is larger than 10 MiB')
    }
    chunks.push(chunk)
  }
  const text = Buffer.concat(chunks).toString('utf8')
  if (text.length === 0) {
    return null
  }
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}
