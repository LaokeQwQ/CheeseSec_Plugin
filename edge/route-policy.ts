export type RouteKind =
  | "assets"
  | "publication"
  | "resource"
  | "origin"
  | "edge-health"
  | "not-found"
  | "misdirected"
  | "method-not-allowed"
  | "forbidden";

export type PublicationClass = "catalog" | "policy" | "schema" | "ota";
export type OriginRole = "console" | "api";

export interface RouteDecision {
  kind: RouteKind;
  hostname: string;
  methodAllowed: boolean;
  allow?: string;
  key?: string;
  publicationClass?: PublicationClass;
  sequenceHeader?: boolean;
  channel?: "stable" | "canary" | "dev";
  digest?: string;
  filename?: string;
  originRole?: OriginRole;
}

const PUBLIC_METHODS = "GET, HEAD";
const PUBLIC_HOSTS = new Set(["cheesesec.com", "www.cheesesec.com", "docs.cheesesec.com"]);
const LOCAL_ASSET_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const PUBLICATION_HOSTS = new Set([
  "store.cheesesec.com",
  "ota.cheesesec.com",
  "res.cheesesec.com",
]);

const PAGE_HOSTS = new Set([...PUBLIC_HOSTS, ...LOCAL_ASSET_HOSTS]);

const STATIC_PUBLICATION_KEYS: ReadonlyMap<string, string> = new Map([
  ["/v1/catalog/index.json", "catalog/index.json"],
  ["/v1/policy/endpoints.json", "policy/endpoints.json"],
  ["/v1/policy/trust-roots.json", "policy/trust-roots.json"],
  ["/v1/policy/source-registry.json", "policy/source-registry.json"],
  ["/v1/policy/revocations.json", "policy/revocations.json"],
]);

const SCHEMA_PATH =
  /^\/v1\/schema\/(store|crp)\/([a-z0-9][a-z0-9-]*)\.schema\.json$/;
const OTA_PATH = /^\/v1\/channels\/(stable|canary|dev)\/index\.json$/;
const RESOURCE_PATH =
  /^\/sha256\/([0-9a-f]{64})\/([A-Za-z0-9][A-Za-z0-9._+-]*)$/;
const CREDENTIAL_QUERY_KEY =
  /^(?:access[_-]?token|api[_-]?key|authorization|cookie|credential|csrf|secret|signature|token)$/i;

function methodDecision(
  kind: RouteKind,
  hostname: string,
  request: Request,
  fields: Omit<Partial<RouteDecision>, "kind" | "hostname" | "methodAllowed"> = {},
): RouteDecision {
  const methodAllowed = request.method === "GET" || request.method === "HEAD";
  return {
    kind: methodAllowed ? kind : "method-not-allowed",
    hostname,
    methodAllowed,
    allow: methodAllowed ? undefined : PUBLIC_METHODS,
    ...fields,
  };
}

function rawPathFromRequest(request: Request): string {
  const match = request.url.match(/^[a-z][a-z\d+.-]*:\/\/[^/]*(\/[^?#]*)?/i);
  return match?.[1] ?? "/";
}

function hasAmbiguousPath(request: Request, pathname: string): boolean {
  const rawPath = rawPathFromRequest(request);

  if (
    rawPath.includes("\\") ||
    rawPath.includes("//") ||
    /%(?:2f|2F|5c|5C|2e|2E)/.test(rawPath)
  ) {
    return true;
  }

  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(rawPath);
  } catch {
    return true;
  }

  if (
    decodedPath !== rawPath &&
    (decodedPath.includes("\\") ||
      decodedPath.includes("//") ||
      decodedPath.split("/").some((segment) => segment === "." || segment === ".."))
  ) {
    return true;
  }

  if (pathname.includes("\\") || pathname.includes("//")) {
    return true;
  }

  return pathname.split("/").some((segment, index, segments) => {
    if (index === 0 || (index === segments.length - 1 && segment === "")) {
      return false;
    }
    return segment === "." || segment === ".." || segment === "";
  });
}

function hasPublicCredential(request: Request, url: URL): boolean {
  if (
    url.username ||
    url.password ||
    request.headers.has("authorization") ||
    request.headers.has("cookie") ||
    request.headers.has("x-csrf-token")
  ) {
    return true;
  }

  for (const key of url.searchParams.keys()) {
    if (CREDENTIAL_QUERY_KEY.test(key)) {
      return true;
    }
  }

  return false;
}

function forbiddenDecision(hostname: string): RouteDecision {
  return {
    kind: "forbidden",
    hostname,
    methodAllowed: false,
  };
}

function classifyPublication(
  request: Request,
  url: URL,
): RouteDecision {
  if (hasAmbiguousPath(request, url.pathname)) {
    return { kind: "not-found", hostname: url.hostname, methodAllowed: false };
  }

  if (hasPublicCredential(request, url)) {
    return forbiddenDecision(url.hostname);
  }

  if (url.hostname === "store.cheesesec.com") {
    const staticKey = STATIC_PUBLICATION_KEYS.get(url.pathname);
    if (staticKey) {
      return methodDecision("publication", url.hostname, request, {
        key: staticKey,
        publicationClass:
          staticKey.startsWith("policy/") ? "policy" : "catalog",
        sequenceHeader: staticKey === "catalog/index.json",
      });
    }

    const schemaMatch = url.pathname.match(SCHEMA_PATH);
    if (schemaMatch) {
      const [scope, name] = schemaMatch.slice(1);
      return methodDecision("publication", url.hostname, request, {
        key: `schema/${scope === "crp" ? "crp-v1" : "store-v1"}/${name}.schema.json`,
        publicationClass: "schema",
      });
    }
  }

  if (url.hostname === "ota.cheesesec.com") {
    const otaMatch = url.pathname.match(OTA_PATH);
    if (otaMatch) {
      const channel = otaMatch[1] as "stable" | "canary" | "dev";
      return methodDecision("publication", url.hostname, request, {
        key: `ota/channels/${channel}/index.json`,
        publicationClass: "ota",
        sequenceHeader: true,
        channel,
      });
    }
  }

  return { kind: "not-found", hostname: url.hostname, methodAllowed: false };
}

function classifyResource(request: Request, url: URL): RouteDecision {
  if (hasAmbiguousPath(request, url.pathname)) {
    return { kind: "not-found", hostname: url.hostname, methodAllowed: false };
  }

  if (hasPublicCredential(request, url)) {
    return forbiddenDecision(url.hostname);
  }

  const resourceMatch = url.pathname.match(RESOURCE_PATH);
  if (!resourceMatch) {
    return { kind: "not-found", hostname: url.hostname, methodAllowed: false };
  }

  const [, digest, filename] = resourceMatch;
  return methodDecision("resource", url.hostname, request, {
    key: `resources/sha256/${digest}/${filename}`,
    digest,
    filename,
  });
}

function isApiOriginPath(pathname: string): boolean {
  return (
    pathname === "/api" ||
    pathname.startsWith("/api/") ||
    pathname === "/health" ||
    pathname === "/health/live" ||
    pathname === "/health/ready" ||
    pathname === "/health/cluster"
  );
}

export function classifyRequest(
  request: Request,
  previewHost = "",
): RouteDecision {
  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const isPreviewHost = Boolean(previewHost) && hostname === previewHost.toLowerCase();

  if (
    url.pathname === "/api/health" &&
    (PAGE_HOSTS.has(hostname) || isPreviewHost)
  ) {
    return {
      kind: request.method === "GET" || request.method === "HEAD"
        ? "edge-health"
        : "method-not-allowed",
      hostname,
      methodAllowed: request.method === "GET" || request.method === "HEAD",
      allow: PUBLIC_METHODS,
    };
  }

  if (PUBLICATION_HOSTS.has(hostname)) {
    if (hostname === "res.cheesesec.com") {
      return classifyResource(request, url);
    }
    return classifyPublication(request, url);
  }

  if (hostname === "api.cheesesec.com") {
    if (!isApiOriginPath(url.pathname)) {
      return { kind: "not-found", hostname, methodAllowed: false };
    }
    return { kind: "origin", hostname, methodAllowed: true, originRole: "api" };
  }

  if (hostname === "console.cheesesec.com") {
    return { kind: "origin", hostname, methodAllowed: true, originRole: "console" };
  }

  if (PAGE_HOSTS.has(hostname) || isPreviewHost) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return {
        kind: "method-not-allowed",
        hostname,
        methodAllowed: false,
        allow: PUBLIC_METHODS,
      };
    }
    return { kind: "assets", hostname, methodAllowed: true };
  }

  return { kind: "misdirected", hostname, methodAllowed: false };
}
