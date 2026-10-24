import { servePublication, serveResource } from "./publication";
import { classifyRequest } from "./route-policy";
import { forbiddenResponse, methodNotAllowed, misdirectedResponse, notFoundResponse } from "./response-policy";
import { serveStorefront } from "./storefront";
import { recordServiceResponse } from "./service-counters";
import { serveServiceStatus } from "./service-status";

export { ServiceCounters } from "./service-counters";

// The store page and read-only v1 API share a host. This service has no
// credentials, arbitrary static-file serving, or management proxy binding.
export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    const status = await serveServiceStatus(request, env);
    if (status) return status;
    const storefront = serveStorefront(request);
    if (storefront) {
      if (new URL(request.url).pathname === "/") recordServiceResponse(request, storefront, env, false, ctx);
      return storefront;
    }
    const decision = classifyRequest(request);
    let response: Response;
    switch (decision.kind) {
      case "publication":
        response = await servePublication(request, env, decision);
        recordServiceResponse(request, response, env, false, ctx);
        return response;
      case "resource":
        response = await serveResource(request, env, decision);
        recordServiceResponse(request, response, env, true, ctx);
        return response;
      case "forbidden": return forbiddenResponse();
      case "method-not-allowed": return methodNotAllowed();
      case "misdirected": return misdirectedResponse();
      default: return notFoundResponse();
    }
  },
};

