import { servePublication, serveResource } from "./publication";
import { classifyRequest } from "./route-policy";
import { forbiddenResponse, methodNotAllowed, misdirectedResponse, notFoundResponse } from "./response-policy";

// This service serves only public metadata and content-addressed files. It
// has no website assets, credentials, origin URL, or management proxy binding.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
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
