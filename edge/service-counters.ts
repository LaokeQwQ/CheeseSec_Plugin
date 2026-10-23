export const SERVICE_HOSTS = {
  "store.cheesesec.com": "store",
  "ota.cheesesec.com": "ota",
  "res.cheesesec.com": "res",
} as const;

export type ServiceName = typeof SERVICE_HOSTS[keyof typeof SERVICE_HOSTS];
type CounterRow = {
  service: ServiceName;
  started_at: string;
  updated_at: string;
  visits: number;
  downloads: number;
  transferred_bytes: number;
};
type CounterDelta = { visits: number; downloads: number; transferred_bytes: number };

export type CounterSnapshot = {
  available: boolean;
  started_at: string | null;
  updated_at: string | null;
  visits: number | null;
  downloads: number | null;
  transferred_bytes: number | null;
};

export function serviceForHost(host: string): ServiceName | undefined {
  return Object.hasOwn(SERVICE_HOSTS, host)
    ? SERVICE_HOSTS[host as keyof typeof SERVICE_HOSTS]
    : undefined;
}

function isService(value: unknown): value is ServiceName {
  return value === "store" || value === "ota" || value === "res";
}

function naturalNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function validSnapshot(value: unknown, service: ServiceName): value is CounterRow {
  if (!value || typeof value !== "object") return false;
  const row = value as CounterRow;
  return row.service === service && naturalNumber(row.visits) && naturalNumber(row.downloads)
    && naturalNumber(row.transferred_bytes) && typeof row.started_at === "string"
    && Number.isFinite(Date.parse(row.started_at)) && typeof row.updated_at === "string"
    && Number.isFinite(Date.parse(row.updated_at));
}

const unavailable = (): CounterSnapshot => ({
  available: false, started_at: null, updated_at: null,
  visits: null, downloads: null, transferred_bytes: null,
});

export function withDeadline<T>(operation: Promise<T>, milliseconds = 3000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("SERVICE_TIMEOUT")), milliseconds);
    operation.then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
  });
}

async function counterCall(env: Env, service: ServiceName, action: "snapshot" | "record", delta?: CounterDelta): Promise<CounterRow> {
  if (!env.SERVICE_COUNTERS) throw new Error("COUNTERS_UNAVAILABLE");
  // There are exactly three object names. Paths, IPs and other request data
  // never become storage keys or leave this Worker for the counter service.
  const stub = env.SERVICE_COUNTERS.get(env.SERVICE_COUNTERS.idFromName(`service:${service}`));
  const operation = stub.fetch(`https://service-counters.invalid/${action}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(3000),
    body: JSON.stringify({ service, ...(delta ? { delta } : {}) }),
  }).then(async response => {
    if (!response.ok) throw new Error("COUNTERS_UNAVAILABLE");
    return response.json();
  });
  const row: unknown = await withDeadline(operation);
  if (!validSnapshot(row, service)) throw new Error("COUNTERS_INVALID");
  return row;
}

export async function readServiceCounters(env: Env, service: ServiceName, visit = false): Promise<CounterSnapshot> {
  try {
    const row = await counterCall(env, service, visit ? "record" : "snapshot", visit ? {
      visits: 1, downloads: 0, transferred_bytes: 0,
    } : undefined);
    const { started_at, updated_at, visits, downloads, transferred_bytes } = row;
    return { available: true, started_at, updated_at, visits, downloads, transferred_bytes };
  } catch {
    return unavailable();
  }
}

export function responseCounterDelta(request: Request, response: Response, resource: boolean): CounterDelta | null {
  if (request.method !== "GET" || !((response.status >= 200 && response.status < 300) || response.status === 304)) return null;
  const length = response.headers.get("content-length");
  const bytes = length !== null && /^\d+$/.test(length) ? Number(length) : NaN;
  const download = resource && (response.status === 200 || response.status === 206)
    && naturalNumber(bytes);
  return { visits: 1, downloads: download ? 1 : 0, transferred_bytes: download ? bytes : 0 };
}

export function recordServiceResponse(request: Request, response: Response, env: Env, resource: boolean, ctx?: ExecutionContext): void {
  const service = serviceForHost(new URL(request.url).hostname);
  const delta = responseCounterDelta(request, response, resource);
  if (!service || !delta || !env.SERVICE_COUNTERS) return;
  // Counting is independent of streaming and must not interrupt a release
  // download if the statistics service is temporarily unavailable.
  const record = counterCall(env, service, "record", delta).then(() => undefined).catch(() => undefined);
  ctx?.waitUntil(record);
}

// A fetch-based Durable Object also runs in the repository's Node test bundle.
// The namespace is created as SQLite by the Wrangler migration. Every update
// and snapshot is one transaction on one row, surviving eviction/restarts.
export class ServiceCounters {
  constructor(private readonly ctx: DurableObjectState) {
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS counters (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      service TEXT NOT NULL,
      started_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      visits INTEGER NOT NULL DEFAULT 0,
      downloads INTEGER NOT NULL DEFAULT 0,
      transferred_bytes INTEGER NOT NULL DEFAULT 0
    )`);
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || (path !== "/snapshot" && path !== "/record")) return new Response(null, { status: 404 });
    let input: { service?: unknown; delta?: CounterDelta };
    try {
      const body = await request.text();
      if (body.length > 256) return new Response(null, { status: 400 });
      input = JSON.parse(body);
      if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error();
    } catch {
      return new Response(null, { status: 400 });
    }
    const { service, delta } = input;
    const expectedKeys = path === "/record" ? ["delta", "service"] : ["service"];
    if (!isService(service) || Object.keys(input).sort().join() !== expectedKeys.join()) return new Response(null, { status: 400 });
    if (path === "/record" && (!delta || Object.keys(delta).sort().join() !== "downloads,transferred_bytes,visits"
      || delta.visits !== 1 || (delta.downloads !== 0 && delta.downloads !== 1)
      || !naturalNumber(delta.transferred_bytes) || (!delta.downloads && delta.transferred_bytes !== 0))) {
      return new Response(null, { status: 400 });
    }
    const row = this.ctx.storage.transactionSync(() => {
      const now = new Date().toISOString();
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO counters (id, service, started_at, updated_at) VALUES (1, ?, ?, ?)", service, now, now);
      const current = this.ctx.storage.sql.exec<CounterRow>("SELECT service, started_at, updated_at, visits, downloads, transferred_bytes FROM counters WHERE id = 1").one();
      if (current.service !== service) return null;
      if (path === "/record" && delta) {
        // Avoid losing integer precision even if totals eventually exceed JS's
        // exact numeric range: refuse the write and expose unavailable totals.
        if (![current.visits + delta.visits, current.downloads + delta.downloads, current.transferred_bytes + delta.transferred_bytes].every(naturalNumber)) return null;
        this.ctx.storage.sql.exec("UPDATE counters SET visits = visits + ?, downloads = downloads + ?, transferred_bytes = transferred_bytes + ?, updated_at = ? WHERE id = 1", delta.visits, delta.downloads, delta.transferred_bytes, now);
      }
      return this.ctx.storage.sql.exec<CounterRow>("SELECT service, started_at, updated_at, visits, downloads, transferred_bytes FROM counters WHERE id = 1").one();
    });
    return row ? Response.json(row, { headers: { "cache-control": "no-store" } }) : new Response(null, { status: 409 });
  }
}
