export type IpFamily = "ipv4" | "ipv6";
export type IpClassification = "ipv4-only" | "ipv6-only" | "dual-stack" | "no-ip" | "unknown";

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/(3[0-2]|[12]?\d))?$/;
const IPV6 = /^[0-9a-f:]*:[0-9a-f:.]*(%[\w.]+)?(\/(12[0-8]|1[01]\d|[1-9]?\d))?$/i;

/** Returns the IP family of an address or CIDR; `undefined` for service tags, `*`, FQDNs etc. */
export function ipFamilyOf(value: string | undefined | null): IpFamily | undefined {
  if (!value) return undefined;
  const v = value.trim();
  if (IPV4.test(v)) return "ipv4";
  if (v.includes(":") && IPV6.test(v)) return "ipv6";
  return undefined;
}

export interface FamilySplit {
  ipv4: string[];
  ipv6: string[];
}

export function splitByFamily(values: Iterable<string | undefined | null>): FamilySplit {
  const out: FamilySplit = { ipv4: [], ipv6: [] };
  const seen = new Set<string>();
  for (const value of values) {
    const family = ipFamilyOf(value);
    if (!family || !value || seen.has(value)) continue;
    seen.add(value);
    out[family].push(value);
  }
  return out;
}

export function classifyAddressing(a: FamilySplit, accessible = true): IpClassification {
  if (!accessible) return "unknown";
  if (a.ipv4.length > 0 && a.ipv6.length > 0) return "dual-stack";
  if (a.ipv4.length > 0) return "ipv4-only";
  if (a.ipv6.length > 0) return "ipv6-only";
  return "no-ip";
}

export function isDefaultRoutePrefix(prefix: string): IpFamily | undefined {
  const p = prefix.trim().toLowerCase();
  if (p === "0.0.0.0/0") return "ipv4";
  if (p === "::/0" || p === "0:0:0:0:0:0:0:0/0") return "ipv6";
  return undefined;
}

function ipv4ToBigInt(ip: string): bigint | undefined {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return undefined;
  return parts.reduce((acc, p) => (acc << 8n) + BigInt(p), 0n);
}

function ipv6ToBigInt(ip: string): bigint | undefined {
  let address = ip.split("%")[0]!.toLowerCase();
  // Embedded IPv4 tail (e.g. ::ffff:10.0.0.1)
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(address);
  if (v4) {
    const n = ipv4ToBigInt(v4[1]!);
    if (n === undefined) return undefined;
    address = `${address.slice(0, -v4[1]!.length)}${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return undefined;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return undefined;
  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n);
}

/** Parses an address (or CIDR) into family, numeric value and prefix length. */
export function parseCidr(value: string): { family: IpFamily; value: bigint; length: number } | undefined {
  const [address, lengthText] = value.trim().split("/");
  if (!address) return undefined;
  const family = ipFamilyOf(address);
  if (!family) return undefined;
  const bits = family === "ipv4" ? 32 : 128;
  const length = lengthText === undefined ? bits : Number(lengthText);
  if (!Number.isInteger(length) || length < 0 || length > bits) return undefined;
  const n = family === "ipv4" ? ipv4ToBigInt(address) : ipv6ToBigInt(address);
  if (n === undefined) return undefined;
  return { family, value: n, length };
}

/** True if the address (or smaller CIDR) lies within the CIDR. Families must match. */
export function cidrContains(cidr: string, candidate: string): boolean {
  const outer = parseCidr(cidr);
  const inner = parseCidr(candidate);
  if (!outer || !inner || outer.family !== inner.family || inner.length < outer.length) return false;
  const bits = BigInt(outer.family === "ipv4" ? 32 : 128);
  const shift = bits - BigInt(outer.length);
  return outer.value >> shift === inner.value >> shift;
}
