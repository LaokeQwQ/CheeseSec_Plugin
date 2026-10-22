export function errorResponse(status: number, code: string): Response {
  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  if (status === 405) {
    headers.set("allow", "GET, HEAD");
  }
  if (status === 421) {
    headers.set("connection", "close");
  }
  return new Response(JSON.stringify({ error: code }), { status, headers });
}

export function methodNotAllowed(): Response {
  return errorResponse(405, "METHOD_NOT_ALLOWED");
}

export function forbiddenResponse(): Response {
  return errorResponse(403, "PUBLIC_ENDPOINT_CREDENTIALS_NOT_ALLOWED");
}

export function misdirectedResponse(): Response {
  return errorResponse(421, "UNKNOWN_EDGE_HOST");
}

export function notFoundResponse(): Response {
  return errorResponse(404, "EDGE_ROUTE_NOT_FOUND");
}

export function noStoreHeaders(source: Headers, requestId?: string): Headers {
  const headers = new Headers();
  for (const [name, value] of source) {
    const lower = name.toLowerCase();
    if (
      lower === "connection" ||
      lower === "keep-alive" ||
      lower === "proxy-authenticate" ||
      lower === "proxy-authorization" ||
      lower === "te" ||
      lower === "trailer" ||
      lower === "transfer-encoding" ||
      lower === "upgrade" ||
      lower === "age" ||
      lower === "cdn-cache-control" ||
      lower === "surrogate-control"
    ) {
      continue;
    }
    headers.set(name, value);
  }
  headers.set("cache-control", "no-store");
  headers.set("cdn-cache-control", "no-store");
  if (requestId) {
    headers.set("x-cheesesec-edge-request-id", requestId);
  }
  return headers;
}
