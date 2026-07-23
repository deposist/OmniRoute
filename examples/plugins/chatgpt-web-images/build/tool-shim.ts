export function prepareToolMessages(
  _body: Record<string, unknown>,
  messages: Array<{ role: string; content: unknown }>
) {
  return { hasTools: false, requestedTools: undefined, effectiveMessages: messages };
}

export async function buildToolModeResponse(response: Response): Promise<Response> {
  return response;
}
