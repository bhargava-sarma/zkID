// The demo's state: a small key-value store with expiry. In memory for the
// local server; Upstash Redis, through its REST API, on Vercel, where requests
// may run in different function instances.

export interface KV {
  get(key: string): Promise<string | null>;
  // Stores value for ttlSeconds. With onlyIfAbsent, leaves an existing key alone.
  // Returns whether it stored the value.
  set(key: string, value: string, ttlSeconds: number, onlyIfAbsent?: boolean): Promise<boolean>;
  incr(key: string): Promise<number>; // no expiry
}

export class MemoryKV implements KV {
  private data = new Map<string, { value: string; expires: number }>();

  private live(key: string) {
    const entry = this.data.get(key);
    if (entry && entry.expires <= Date.now()) {
      this.data.delete(key);
      return undefined;
    }
    return entry;
  }

  async get(key: string) {
    return this.live(key)?.value ?? null;
  }

  async set(key: string, value: string, ttlSeconds: number, onlyIfAbsent = false) {
    if (onlyIfAbsent && this.live(key)) return false;
    this.data.set(key, { value, expires: Date.now() + ttlSeconds * 1000 });
    return true;
  }

  async incr(key: string) {
    const n = Number(this.live(key)?.value ?? 0) + 1;
    this.data.set(key, { value: String(n), expires: Infinity });
    return n;
  }
}

export class UpstashKV implements KV {
  private url: string;
  private token: string;

  constructor(url: string, token: string) {
    this.url = url;
    this.token = token;
  }

  private async command(...args: (string | number)[]): Promise<unknown> {
    const res = await fetch(this.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(args),
    });
    const body = (await res.json().catch(() => null)) as { result?: unknown; error?: string } | null;
    if (!res.ok || !body || body.error !== undefined) {
      throw new Error(`Redis ${args[0]} failed: ${body?.error ?? `HTTP ${res.status}`}`);
    }
    return body.result;
  }

  async get(key: string) {
    return (await this.command('GET', key)) as string | null;
  }

  async set(key: string, value: string, ttlSeconds: number, onlyIfAbsent = false) {
    return (await this.command('SET', key, value, 'EX', ttlSeconds, ...(onlyIfAbsent ? ['NX'] : []))) === 'OK';
  }

  async incr(key: string) {
    return Number(await this.command('INCR', key));
  }
}
