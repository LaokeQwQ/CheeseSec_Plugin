/// <reference types="@cloudflare/workers-types" />
interface Env {
  PUBLICATION_INDEX: R2Bucket;
  PUBLIC_RESOURCES: R2Bucket;
  EDGE_POLICY_VERSION: string;
  SERVICE_COUNTERS?: DurableObjectNamespace;
}
declare module "*.html" { const text: string; export default text; }
declare module "*.css" { const text: string; export default text; }
declare module "*.js" { const text: string; export default text; }
declare module "*.mjs" { const text: string; export default text; }
declare module "*.png" { const bytes: Uint8Array; export default bytes; }
declare module "*.svg" { const text: string; export default text; }
