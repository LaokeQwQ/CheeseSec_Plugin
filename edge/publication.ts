import { errorResponse } from "./response-policy";
import type { RouteDecision } from "./route-policy";

type ParsedRange =
  | { kind: "offset"; offset: number; length?: number }
  | { kind: "suffix"; suffix: number }
  | { kind: "invalid" };

function responseHeaders(
  object: R2Object,
  fallbackContentType: string,
  cacheControl: string,
  env: Env,
): Headers {
  const headers = new Headers();

  if (typeof object.writeHttpMetadata === "function") {
    object.writeHttpMetadata(headers);
  }
  if (!headers.has("content-type")) {
    headers.set("content-type", fallbackContentType);
  }

  const etag = object.httpEtag || (object.etag ? `"${object.etag}"` : "");
  if (etag) {
    headers.set("etag", etag);
  }
  if (
    object.uploaded instanceof Date &&
    !Number.isNaN(object.uploaded.valueOf())
  ) {
    headers.set("last-modified", object.uploaded.toUTCString());
  }
  headers.set("cache-control", cacheControl);
  headers.set("x-content-type-options", "nosniff");
  if (env.EDGE_POLICY_VERSION) {
    headers.set("x-cheesesec-edge-policy", env.EDGE_POLICY_VERSION);
  }
  return headers;
}

function matchesEtag(ifNoneMatch: string, etag: string): boolean {
  if (ifNoneMatch.trim() === "*") {
    return true;
  }
  return ifNoneMatch.split(",").some((candidate) => {
    const normalized = candidate.trim().replace(/^W\//i, "");
    return normalized === etag;
  });
}

function isBodyObject(
  object: R2Object | R2ObjectBody | null,
): object is R2ObjectBody {
  return Boolean(object && "body" in object && object.body);
}

function publicationCacheControl(decision: RouteDecision): string {
  if (decision.publicationClass === "schema") {
    return "public, max-age=300, s-maxage=300, must-revalidate";
  }
  return "public, max-age=60, s-maxage=60, must-revalidate";
}

function sequenceFor(object: R2Object, decision: RouteDecision): string | undefined {
  if (!decision.sequenceHeader) {
    return undefined;
  }
  const metadata = object.customMetadata ?? {};
  const sequence = metadata.index_sequence ?? metadata.sequence;
  return sequence && /^\d+$/.test(sequence) ? sequence : undefined;
}

export async function servePublication(
  request: Request,
  env: Env,
  decision: RouteDecision,
): Promise<Response> {
  if (!env.PUBLICATION_INDEX || !decision.key) {
    return errorResponse(503, "PUBLICATION_BINDING_UNAVAILABLE");
  }

  const object = await env.PUBLICATION_INDEX.get(decision.key);
  if (!object || !isBodyObject(object)) {
    return errorResponse(404, "PUBLICATION_NOT_FOUND");
  }

  const headers = responseHeaders(
    object,
    "application/json; charset=utf-8",
    publicationCacheControl(decision),
    env,
  );
  headers.set("content-length", String(object.size));

  const sequence = sequenceFor(object, decision);
  if (sequence) {
    headers.set("x-cheesesec-index-sequence", sequence);
  }

  const etag = headers.get("etag");
  const ifNoneMatch = request.headers.get("if-none-match");
  if (etag && ifNoneMatch && matchesEtag(ifNoneMatch, etag)) {
    return new Response(null, { status: 304, headers });
  }

  if (request.method === "HEAD") {
    return new Response(null, { status: 200, headers });
  }
  return new Response(object.body, { status: 200, headers });
}

function parseRange(value: string | null): ParsedRange | null {
  if (!value) {
    return null;
  }
  if (value.includes(",")) {
    return { kind: "invalid" };
  }
  const match = value.match(/^bytes=(\d*)-(\d*)$/);
  if (!match || (match[1] === "" && match[2] === "")) {
    return { kind: "invalid" };
  }
  const start = match[1] === "" ? undefined : Number(match[1]);
  const end = match[2] === "" ? undefined : Number(match[2]);
  if (
    (start !== undefined && !Number.isSafeInteger(start)) ||
    (end !== undefined && !Number.isSafeInteger(end)) ||
    (start !== undefined && end !== undefined && start > end)
  ) {
    return { kind: "invalid" };
  }
  if (start === undefined) {
    return end && end > 0
      ? { kind: "suffix", suffix: end }
      : { kind: "invalid" };
  }
  return {
    kind: "offset",
    offset: start,
    length: end === undefined ? undefined : end - start + 1,
  };
}

function resolvedRange(range: ParsedRange, size: number): {
  offset: number;
  length: number;
} | null {
  if (range.kind === "invalid" || size === 0) {
    return null;
  }
  if (range.kind === "suffix") {
    const length = Math.min(range.suffix, size);
    return { offset: size - length, length };
  }
  if (range.offset >= size) {
    return null;
  }
  return {
    offset: range.offset,
    length: Math.min(range.length ?? size, size - range.offset),
  };
}

function ifRangeMatches(value: string, object: R2Object): boolean {
  if (value.startsWith('"') || value.startsWith("W/")) {
    return value === object.httpEtag;
  }
  const date = Date.parse(value);
  return Number.isFinite(date) && Math.floor(object.uploaded.getTime() / 1000) === Math.floor(date / 1000);
}

export async function serveResource(
  request: Request,
  env: Env,
  decision: RouteDecision,
): Promise<Response> {
  if (!env.PUBLIC_RESOURCES || !decision.key) {
    return errorResponse(503, "RESOURCE_BINDING_UNAVAILABLE");
  }

  // Resolve conditions and bounds before opening a range body. R2 may reject
  // unsatisfiable ranges, and its optional range fields can be present but
  // undefined; neither the status nor Content-Range should depend on them.
  const metadata = await env.PUBLIC_RESOURCES.head(decision.key);
  if (!metadata) {
    return errorResponse(404, "RESOURCE_NOT_FOUND");
  }

  const headers = responseHeaders(
    metadata,
    "application/octet-stream",
    "public, max-age=31536000, immutable",
    env,
  );
  headers.set("accept-ranges", "bytes");
  headers.set("content-length", String(metadata.size));

  const etag = headers.get("etag");
  const ifNoneMatch = request.headers.get("if-none-match");
  if (etag && ifNoneMatch && matchesEtag(ifNoneMatch, etag)) {
    return new Response(null, { status: 304, headers });
  }

  if (request.method === "HEAD") {
    // Range applies to GET only; HEAD describes the complete representation.
    return new Response(null, { status: 200, headers });
  }

  const ifRange = request.headers.get("if-range");
  const parsedRange = ifRange && !ifRangeMatches(ifRange, metadata)
    ? null
    : parseRange(request.headers.get("range"));
  const range = parsedRange ? resolvedRange(parsedRange, metadata.size) : null;
  if (parsedRange && !range) {
    headers.set("content-range", `bytes */${metadata.size}`);
    headers.set("content-length", "0");
    headers.set("cache-control", "no-store");
    return new Response(null, { status: 416, headers });
  }

  const object = await env.PUBLIC_RESOURCES.get(
    decision.key,
    range ? { range } : undefined,
  );
  if (!object || !isBodyObject(object)) {
    return errorResponse(404, "RESOURCE_NOT_FOUND");
  }
  // Public digest keys are immutable. Fail closed if an incorrectly replaced
  // object changed between HEAD and GET instead of sending mismatched metadata.
  if (object.size !== metadata.size || object.etag !== metadata.etag) {
    return errorResponse(503, "RESOURCE_VERSION_CHANGED");
  }

  const status = range ? 206 : 200;
  if (range) {
    headers.set("content-length", String(range.length));
    headers.set("content-range", `bytes ${range.offset}-${range.offset + range.length - 1}/${metadata.size}`);
  }
  return new Response(object.body, { status, headers });
}
