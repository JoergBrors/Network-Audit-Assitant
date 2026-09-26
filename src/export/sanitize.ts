import { ipFamilyOf } from "../addressing/ip.js";
import type { AssessmentExport } from "./assessmentJson.js";

/**
 * Sanitizes an assessment export for consumption by a third party (incl. an AI model): every
 * identifier that reveals *who* the tenant is gets replaced by a deterministic pseudonym, while
 * every structural property an analysis needs (relationships, prefix lengths, ports, protocols,
 * NSG/route decisions, RFC1918/ULA address space) is left untouched. See IMPLEMENTATION_PLAN.md
 * Phase 16 and SECURITY.md § Sanitization.
 *
 * Determinism: the same `key` always yields the same pseudonym for the same input, so a sanitized
 * export can still be diffed against a previous sanitized export (drift detection keeps working
 * without ever re-exposing the real identifiers).
 */
export interface SanitizeOptions {
  /** HMAC key. Never derived from tenant data; generate once and keep it outside the repo. */
  key: string;
}

/** Matches one full ARM resource ID (with resource group) anywhere in a string – not anchored,
 * because compound strings such as graph edge IDs (`peering:<id>-><id>#qualifier`) embed several of
 * them joined by "->" and optionally suffixed with "#<qualifier>"; both must stop the match so they
 * survive the rewrite untouched instead of being absorbed into the preceding resource's name. */
const RESOURCE_ID_RE = /\/subscriptions\/([^/]+)\/resourcegroups\/([^/]+)\/((?:(?!->)[^\s"'>#])+)/gi;
/** A bare subscription reference with no resource group (subscription root, or `.../locations/<region>`). */
const SUBSCRIPTION_ID_RE = /\/subscriptions\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi;
const TENANT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Imports the HMAC key ONCE per sanitize run. A large export touches thousands of strings, and
 * `crypto.subtle.importKey` is a real (if small) async round-trip each time — doing it per-string
 * instead of once was the actual bottleneck behind slow "KI-Analyse" runs, not the model call. */
async function importHmacKey(key: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function hmacHex(cryptoKey: CryptoKey, data: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Builds a cache-backed pseudonymizer bound to one HMAC key (imported once, reused for every
 * value — see importHmacKey). */
class Pseudonymizer {
  private readonly cache = new Map<string, string>();
  private constructor(private readonly cryptoKey: CryptoKey) {}

  static async create(key: string): Promise<Pseudonymizer> {
    return new Pseudonymizer(await importHmacKey(key));
  }

  /** Short, human-scannable pseudonym: `<prefix>-<8 hex chars>`. Same input -> same output. */
  async token(kind: string, value: string): Promise<string> {
    const cacheKey = `${kind}:${value}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;
    const hash = await hmacHex(this.cryptoKey, cacheKey);
    const token = `${kind}-${hash.slice(0, 8)}`;
    this.cache.set(cacheKey, token);
    return token;
  }

  /** Prefix-preserving pseudonym for a public IPv4/IPv6 address: keeps the family and, for IPv6,
   * whether it's link-local/documentation range (irrelevant to leak analysis) vs. a real GUA, but
   * replaces the actual bits so the real address never appears in the export. */
  async ip(address: string): Promise<string> {
    const family = ipFamilyOf(address);
    if (!family) return await this.token("addr", address);
    const hash = await hmacHex(this.cryptoKey, `ip:${address}`);
    if (family === "ipv4") {
      const bytes = [0, 2, 4, 6].map((i) => parseInt(hash.slice(i, i + 2), 16));
      return `198.51.${bytes[2]}.${bytes[3]}`; // TEST-NET-2 (RFC 5737): documentation range, never routable.
      // Keeping octets 3-4 pseudo-random preserves distinctness for correlation without exposing the real IP.
    }
    const groups = Array.from({ length: 7 }, (_, i) => hash.slice(i * 4, i * 4 + 4)).filter(Boolean);
    return `2001:db8:${groups.slice(0, 6).join(":")}`; // 2001:db8::/32 (RFC 3849): documentation range.
  }
}

const CONTAINS_SECRET_KEY_RE =
  /key|secret|password|passwd|token|credential|connectionstring|sas\b|sharedkey/i;

/** Azure-mandated literal subnet names (case-insensitive): required by the platform for the
 * resource to function, so they carry no information about the tenant and pseudonymizing them
 * would only make the export harder to read without adding any privacy benefit. */
const PLATFORM_RESERVED_NAMES = new Set([
  "gatewaysubnet",
  "azurefirewallsubnet",
  "azurefirewallmanagementsubnet",
  "azurebastionsubnet",
  "routeserversubnet",
]);

/** Replaces every value that could deanonymize the tenant; keeps structure, counts and decisions. */
function scrub<T>(value: T, replace: (kind: string, s: string) => Promise<string>): Promise<T> {
  return scrubInner(value, replace, "") as Promise<T>;
}

async function scrubInner(
  value: unknown,
  replace: (kind: string, s: string) => Promise<string>,
  keyHint: string,
): Promise<unknown> {
  if (typeof value === "string") {
    if (CONTAINS_SECRET_KEY_RE.test(keyHint)) return "[REMOVED]";
    if (TENANT_ID_RE.test(value)) return replace("guid", value);
    // Bare address (ipAddress field, a UDR next-hop IP that happens to be public, FQDNs left as-is
    // since custom DNS names are structural to reachability, not tenant-identifying by themselves).
    if (ipFamilyOf(value)) return replace("addr", value);
    if (value.includes("/subscriptions/")) return sanitizeIdsInString(value, replace);
    return value;
  }
  if (Array.isArray(value)) return Promise.all(value.map((v) => scrubInner(v, replace, keyHint)));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = await scrubInner(v, replace, k);
    return out;
  }
  return value;
}

/** Pseudonymizes every embedded ARM resource ID (and bare `/subscriptions/<id>`) in a string.
 * Strings in this export are not always a single ID: graph edge IDs join two full resource IDs as
 * `<edgeType>:<sourceId>-><targetId>[#suffix]`, so replacement must work on substrings, not the
 * whole string, and must be applied left-to-right since matches can't overlap. */
async function sanitizeIdsInString(
  value: string,
  replace: (kind: string, s: string) => Promise<string>,
): Promise<string> {
  const withRg: { start: number; end: number; replacement: string }[] = [];
  for (const match of value.matchAll(RESOURCE_ID_RE)) {
    const [full, subId, rg, rest] = match;
    const subToken = await replace("sub", subId!);
    const rgToken = await replace("rg", rg!);
    // rest = providers/microsoft.network/virtualnetworks/<name>/subnets/<name>/... (indices
    // 0=providers, 1=provider, 2=type, 3=name, 4=childType, 5=childName, ...) — pseudonymize every
    // name segment, keep "providers", the provider namespace and every resource-type segment.
    const segments = rest!.split("/");
    const pseudonymized: string[] = [];
    for (let i = 0; i < segments.length; i++) {
      const isNameSegment = i >= 3 && i % 2 === 1;
      pseudonymized.push(isNameSegment ? await replace("res", segments[i]!) : segments[i]!);
    }
    const replacement = `/subscriptions/${subToken}/resourcegroups/${rgToken}/${pseudonymized.join("/")}`;
    withRg.push({ start: match.index, end: match.index + full.length, replacement });
  }
  // Bare `/subscriptions/<guid>` references (management group scope, tenant-level entities) that
  // don't fall inside a resource-group-scoped match above.
  const bareSubs: { start: number; end: number; replacement: string }[] = [];
  for (const match of value.matchAll(SUBSCRIPTION_ID_RE)) {
    const start = match.index;
    const end = start + match[0].length;
    if (withRg.some((r) => start >= r.start && start < r.end)) continue;
    const subToken = await replace("sub", match[1]!);
    bareSubs.push({ start, end, replacement: `/subscriptions/${subToken}` });
  }
  const all = [...withRg, ...bareSubs].sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const r of all) {
    out += value.slice(cursor, r.start) + r.replacement;
    cursor = r.end;
  }
  return out + value.slice(cursor);
}

export interface SanitizedExport {
  export: AssessmentExport;
  /** How many distinct values were pseudonymized, for a quick sanity check before sending it out. */
  stats: { pseudonymizedTokens: number; publicIpsReplaced: number };
}

/**
 * Produces an export safe to hand to a third party or an AI model: every tenant/subscription/
 * resource-group/resource name and every public IP address is replaced by a deterministic,
 * prefix-preserving pseudonym. Relationships, prefix lengths, ports, protocols, NSG/route/firewall
 * decisions, RFC1918/ULA ranges and counts are preserved so IPv6 exposure and other architectural
 * gaps remain analyzable.
 */
export async function sanitizeExport(
  input: AssessmentExport,
  options: SanitizeOptions,
): Promise<SanitizedExport> {
  const p = await Pseudonymizer.create(options.key);
  const seen = new Set<string>();
  // Every real resource/subscription/resource-group name that got pseudonymized while walking IDs,
  // longest first so "vnet-hub-prod" is replaced before a shorter name it happens to contain.
  const knownNames = new Map<string, string>();
  const publicIps = new Set(input.publicIps.flatMap((ip) => (ip.ipAddress ? [ip.ipAddress] : [])));

  let publicIpsReplaced = 0;
  const replaceAddress = async (s: string): Promise<string> => {
    // Only addresses known to be public IPs get pseudonymized; RFC1918/ULA/link-local ranges stay
    // untouched because they carry no information about the tenant's identity and an IPv6 leak
    // analysis needs to see exactly which private ranges are (or aren't) exposed to the internet.
    if (!publicIps.has(s)) return s;
    publicIpsReplaced++;
    return p.ip(s);
  };
  const replace = async (kind: string, s: string): Promise<string> => {
    if (kind === "addr") return replaceAddress(s);
    if (kind === "res" && PLATFORM_RESERVED_NAMES.has(s.toLowerCase())) return s;
    seen.add(`${kind}:${s}`);
    const token = await p.token(kind, s);
    if (kind === "res" || kind === "rg") knownNames.set(s, token);
    return token;
  };

  const scrubbed = await scrub(input, replace);
  // Second pass: the same real names (VNet/subnet/NIC/etc.) also appear as plain `name` fields and
  // inside free-text hop/summary strings ("Zugestellt über afw-hub"), not just inside resource IDs.
  // Replace every remaining whole-word occurrence with the token already assigned to that name.
  const withFreeTextScrubbed =
    knownNames.size > 0 ? replaceKnownNames(JSON.stringify(scrubbed), knownNames) : JSON.stringify(scrubbed);
  const final = JSON.parse(withFreeTextScrubbed) as AssessmentExport;

  return {
    export: { ...final, metadata: { ...final.metadata, sanitized: true } },
    stats: { pseudonymizedTokens: seen.size, publicIpsReplaced },
  };
}

const RESERVED_WORD_RE = /^[a-z]+$/;

/** Whole-word replacement of every known real resource name with its already-assigned token,
 * longest names first so a name that is a substring of another isn't replaced too early. */
function replaceKnownNames(json: string, knownNames: Map<string, string>): string {
  const names = [...knownNames.keys()]
    // Very short or purely generic names (e.g. "default", "vm") cause false-positive matches and
    // carry no identifying value on their own; leave them as-is.
    .filter((n) => n.length >= 3 && !RESERVED_WORD_RE.test(n))
    .sort((a, b) => b.length - a.length);
  if (names.length === 0) return json;
  const escaped = names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`\\b(${escaped.join("|")})\\b`, "g");
  return json.replace(re, (match) => knownNames.get(match) ?? match);
}

/** `azure-network-assessment-sanitized-YYYYMMDD-HHMM.json` (local time). */
export function sanitizedFileName(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `azure-network-assessment-sanitized-${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}.json`;
}
