import { cidrContains, ipFamilyOf } from "../addressing/ip.js";
import type { AvnmAdminRuleEntity, NsgEntity, NsgRuleEntity } from "../models/network.js";
import type { Confidence } from "../models/path.js";

export interface FlowTuple {
  source: string;
  destination: string;
  protocol: "Tcp" | "Udp" | "Icmp" | "*";
  port: number;
  /** Address ranges treated as "VirtualNetwork" service tag (own VNet, peered VNets, on-prem prefixes). */
  virtualNetworkPrefixes: string[];
  /** ASG membership of the source / destination NIC, if known. */
  sourceAsgIds?: string[] | undefined;
  destinationAsgIds?: string[] | undefined;
  /** Resolves service tags (AzureCloud, Storage.WestEurope, …) to prefixes; undefined = unknown tag. */
  resolveTag?: ((tag: string) => string[] | undefined) | undefined;
}

export interface NsgDecision {
  /** AlwaysAllow only occurs for AVNM security admin rules. */
  access: "Allow" | "Deny" | "AlwaysAllow";
  rule: string;
  priority: number;
  isDefault: boolean;
  confidence: Confidence;
  note?: string | undefined;
}

const AZURE_LB = "168.63.129.16";

/** Standard default rules (used when the inventory lacks them). */
export const DEFAULT_NSG_RULES: NsgRuleEntity[] = [
  rule("AllowVnetInBound", "Inbound", "Allow", 65000, ["VirtualNetwork"], ["VirtualNetwork"]),
  rule("AllowAzureLoadBalancerInBound", "Inbound", "Allow", 65001, ["AzureLoadBalancer"], ["*"]),
  rule("DenyAllInBound", "Inbound", "Deny", 65500, ["*"], ["*"]),
  rule("AllowVnetOutBound", "Outbound", "Allow", 65000, ["VirtualNetwork"], ["VirtualNetwork"]),
  rule("AllowInternetOutBound", "Outbound", "Allow", 65001, ["*"], ["Internet"]),
  rule("DenyAllOutBound", "Outbound", "Deny", 65500, ["*"], ["*"]),
];

function rule(
  name: string,
  direction: string,
  access: string,
  priority: number,
  sources: string[],
  destinations: string[],
): NsgRuleEntity {
  return {
    name,
    direction,
    access,
    priority,
    protocol: "*",
    sources,
    destinations,
    sourcePorts: ["*"],
    destinationPorts: ["*"],
    sourceAsgIds: [],
    destinationAsgIds: [],
    ipFamilies: ["any"],
    isDefault: true,
  };
}

type Match = "yes" | "no" | "unknown";

function addressMatches(
  prefix: string,
  address: string,
  vnetPrefixes: string[],
  resolveTag?: FlowTuple["resolveTag"],
): Match {
  const p = prefix.trim();
  const lower = p.toLowerCase();
  if (lower === "*" || lower === "any") return "yes";
  if (lower === "virtualnetwork") return vnetPrefixes.some((v) => cidrContains(v, address)) ? "yes" : "no";
  if (lower === "internet") {
    // Everything outside the VirtualNetwork space (simplification of the Internet service tag).
    return vnetPrefixes.some((v) => cidrContains(v, address)) || isPrivate(address) ? "no" : "yes";
  }
  if (lower === "azureloadbalancer") return address === AZURE_LB ? "yes" : "no";
  const family = ipFamilyOf(p);
  if (family)
    return family === ipFamilyOf(address) &&
      cidrContains(p.includes("/") ? p : `${p}/${family === "ipv4" ? 32 : 128}`, address)
      ? "yes"
      : "no";
  // Other service tags (AzureCloud, Storage, …): resolved via the Service Tag Discovery API data.
  const prefixes = resolveTag?.(p);
  if (!prefixes) return "unknown";
  return prefixes.some((x) => ipFamilyOf(x.split("/")[0]) === ipFamilyOf(address) && cidrContains(x, address))
    ? "yes"
    : "no";
}

function isPrivate(address: string): boolean {
  return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"].some(
    (p) => cidrContains(p, address),
  );
}

function portMatches(ranges: string[], port: number): boolean {
  return ranges.some((r) => {
    if (r === "*" || r === "") return true;
    const [lo, hi] = r.split("-").map(Number);
    return hi === undefined ? lo === port : port >= lo! && port <= hi;
  });
}

function protocolMatches(ruleProtocol: string, protocol: FlowTuple["protocol"]): boolean {
  const p = ruleProtocol.toLowerCase();
  return p === "*" || protocol === "*" || p === protocol.toLowerCase();
}

function side(
  prefixes: string[],
  asgIds: string[],
  address: string,
  memberAsgs: string[] | undefined,
  vnet: string[],
  resolveTag?: FlowTuple["resolveTag"],
): Match {
  if (asgIds.length > 0) {
    if (!memberAsgs) return "unknown";
    return asgIds.some((a) => memberAsgs.includes(a)) ? "yes" : "no";
  }
  let result: Match = "no";
  for (const p of prefixes) {
    const m = addressMatches(p, address, vnet, resolveTag);
    if (m === "yes") return "yes";
    if (m === "unknown") result = "unknown";
  }
  return result;
}

/**
 * Evaluates rules for one flow and direction: ascending priority, first match wins. Rules that might
 * match (unresolved service tags / ASGs) lower the confidence of the decision.
 */
export function evaluateRules(
  rules: NsgRuleEntity[],
  direction: "Inbound" | "Outbound",
  flow: FlowTuple,
): NsgDecision | undefined {
  const ordered = rules
    .filter((r) => r.direction.toLowerCase() === direction.toLowerCase())
    .sort((a, b) => a.priority - b.priority);
  let uncertain: string | undefined;
  for (const r of ordered) {
    if (!protocolMatches(r.protocol, flow.protocol) || !portMatches(r.destinationPorts, flow.port)) continue;
    const src = side(
      r.sources,
      r.sourceAsgIds,
      flow.source,
      flow.sourceAsgIds,
      flow.virtualNetworkPrefixes,
      flow.resolveTag,
    );
    const dst = side(
      r.destinations,
      r.destinationAsgIds,
      flow.destination,
      flow.destinationAsgIds,
      flow.virtualNetworkPrefixes,
      flow.resolveTag,
    );
    if (src === "no" || dst === "no") continue;
    if (src === "unknown" || dst === "unknown") {
      uncertain ??= r.name;
      continue;
    }
    const access = r.access.toLowerCase();
    return {
      access: access === "deny" ? "Deny" : access === "alwaysallow" ? "AlwaysAllow" : "Allow",
      rule: r.name,
      priority: r.priority,
      isDefault: r.isDefault,
      confidence: uncertain ? "POSSIBLE" : "CONFIRMED",
      note: uncertain
        ? `Regel „${uncertain}“ mit höherer Priorität könnte greifen (Service Tag/ASG nicht auflösbar)`
        : undefined,
    };
  }
  return undefined;
}

/** NSG = explicit rules plus Azure default rules. */
export function evaluateNsg(
  nsg: NsgEntity | undefined,
  direction: "Inbound" | "Outbound",
  flow: FlowTuple,
): NsgDecision | undefined {
  if (!nsg) return undefined;
  const defaults = nsg.defaultRules.length > 0 ? nsg.defaultRules : DEFAULT_NSG_RULES;
  return evaluateRules([...nsg.rules, ...defaults], direction, flow);
}

/**
 * AVNM security admin rules (evaluated before NSGs): Deny stops, AlwaysAllow delivers without NSG
 * evaluation, Allow continues to the NSGs (Microsoft Learn: concept-security-admins).
 */
export function evaluateAdminRules(
  rules: AvnmAdminRuleEntity[],
  direction: "Inbound" | "Outbound",
  flow: FlowTuple,
): NsgDecision | undefined {
  return evaluateRules(
    rules.map((r) => ({
      name: `AVNM ${r.name}`,
      direction: r.direction,
      access: r.access,
      priority: r.priority,
      protocol: r.protocol.toLowerCase() === "any" ? "*" : r.protocol,
      sources: r.sources.length ? r.sources : ["*"],
      destinations: r.destinations.length ? r.destinations : ["*"],
      sourcePorts: r.sourcePorts.length ? r.sourcePorts : ["*"],
      destinationPorts: r.destinationPorts.length ? r.destinationPorts : ["*"],
      sourceAsgIds: [],
      destinationAsgIds: [],
      ipFamilies: ["any"],
      isDefault: false,
    })),
    direction,
    flow,
  );
}
