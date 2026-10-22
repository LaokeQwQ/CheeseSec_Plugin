import { servePublication, serveResource } from "./publication";
import { classifyRequest } from "./route-policy";
import { forbiddenResponse, methodNotAllowed, misdirectedResponse, notFoundResponse } from "./response-policy";
import { serveStorefront } from "./storefront";

// The store page and read-only v1 API share a host. This service has no
// credentials, arbitrary static-file serving, or management proxy binding.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const storefront = serveStorefront(request);
    if (storefront) return storefront;
    const decision = classifyRequest(request);
    switch (decision.kind) {
      case "publication": return servePublication(request, env, decision);
      case "resource": return serveResource(request, env, decision);
      case "forbidden": return forbiddenResponse();
      case "method-not-allowed": return methodNotAllowed();
      case "misdirected": return misdirectedResponse();
      default: return notFoundResponse();
    }
  },
};
