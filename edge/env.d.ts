/// <reference types="@cloudflare/workers-types" />
interface Env {
  PUBLICATION_INDEX: R2Bucket;
  PUBLIC_RESOURCES: R2Bucket;
  EDGE_POLICY_VERSION: string;
}
