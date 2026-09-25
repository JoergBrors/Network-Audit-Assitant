import { cidrContains, ipFamilyOf } from "../addressing/ip.js";
import type { FirewallEntity, FirewallRuleEntity } from "../models/network.js";
import type { Confidence, Evidence } from "../models/path.js";
import { tagResolver, type RoutingContext } from "../routing/context.js";

export interface FirewallDecision {
  access: "Allow" | "Deny" | "Unknown";
  rule?: string | undefined;
  confidence: Confidence;
  evidence: Evidence[];
}

interface OrderedCollection {
  group: string;
  collection: string;
  type: string;
  action: string;
  rules: FirewallRuleEntity[];
}

/**
 * Collections in processing order: parent policy before child policy, then rule collection group
 * priority, then rule collection priority (Azure Firewall policy hierarchy).
 */
function orderedCollections(
  ctx: RoutingContext,
  policyId: string,
  seen = new Set<string>(),
): OrderedCollection[] {
  if (seen.has(policyId)) return [];
  seen.add(policyId);
  const policy = ctx.firewallPolicies.get(policyId);
  if (!policy) return [];
  const parent = policy.basePolicyId ? orderedCollections(ctx, policy.basePolicyId, seen) : [];
  const groups = policy.ruleCollectionGroupIds
    .map((id) => ctx.ruleCollectionGroups.get(id))
    .filter((g): g is NonNullable<typeof g> => g !== undefined)
    .sort((a, b) => (a.priority ?? 65000) - (b.priority ?? 65000));
  const own = groups.flatMap((g) =>
    [...g.ruleCollections]
      .sort((a, b) => (a.priority ?? 65000) - (b.priority ?? 65000))
      .map((c) => ({
        group: g.name,
        collection: c.name,
        type: c.collectionType,
        action: c.action ?? "Allow",
        rules: c.rules,
      })),
  );
  return [...parent, ...own];
}

function addressList(ctx: RoutingContext, addresses: string[], ipGroupIds: string[]): string[] {
  return [...addresses, ...ipGroupIds.flatMap((id) => ctx.ipGroups.get(id.toLowerCase())?.ipAddresses ?? [])];
}

type Match = "yes" | "no" | "unknown";

function matchAddress(
  list: string[],
  address: string,
  internet: boolean,
  resolveTag?: (t: string) => string[] | undefined,
): Match {
  if (list.length === 0) return "no";
  let result: Match = "no";
  for (const raw of list) {
    const a = raw.trim().toLowerCase();
    if (a === "*" || a === "any") return "yes";
    const family = ipFamilyOf(a);
    if (family) {
      if (family !== ipFamilyOf(address)) continue;
      const cidr = a.includes("/") ? a : `${a}/${family === "ipv4" ? 32 : 128}`;
      if (cidrContains(cidr, address)) return "yes";
      continue;
    }
    if (a === "internet" && internet) return "yes";
    const prefixes = resolveTag?.(raw.trim());
    if (prefixes) {
      if (
        prefixes.some((p) => ipFamilyOf(p.split("/")[0]) === ipFamilyOf(address) && cidrContains(p, address))
      )
        return "yes";
      continue;
    }
    result = "unknown"; // unresolved service tags / FQDNs
  }
  return result;
}

function matchPort(ports: string[], protocols: string[], protocol: string, port: number): boolean {
  const protoOk =
    protocols.length === 0 ||
    protocols.some((p) => {
      const name = p.split(":")[0]!.toLowerCase();
      return name === "any" || name === protocol.toLowerCase() || protocol === "*";
    });
  const portOk =
    ports.length === 0 ||
    ports.some((r) => {
      if (r === "*") return true;
      const [lo, hi] = r.split("-").map(Number);
      return hi === undefined ? lo === port : port >= lo! && port <= hi;
    });
  return protoOk && portOk;
}

/**
 * Best-effort evaluation of Azure Firewall policy rules for one flow (ARCHITECTURE.md § 12.3).
 * Network rules are evaluated first (IP/port/protocol). Application rules depend on FQDNs and can
 * only be assessed as LIKELY/POSSIBLE. The firewall is primarily a control point; the rule verdict
 * refines, but never replaces, that statement.
 */
export function evaluateFirewall(
  ctx: RoutingContext,
  fw: FirewallEntity,
  flow: { source: string; destination: string; protocol: string; port: number; internet: boolean },
): FirewallDecision {
  const family = ipFamilyOf(flow.destination);
  const evidence: Evidence[] = [];
  if (!fw.firewallPolicyId) {
    const classic = fw.classicRuleCollections.network + fw.classicRuleCollections.application;
    return {
      access: "Unknown",
      confidence: "UNKNOWN",
      evidence: [
        {
          kind: "missing-data",
          resourceId: fw.id,
          description:
            classic > 0
              ? "Classic-Firewall-Regeln werden noch nicht ausgewertet"
              : "Keine Firewall Policy zugeordnet",
        },
      ],
    };
  }
  const collections = orderedCollections(ctx, fw.firewallPolicyId);
  if (collections.length === 0) {
    return {
      access: "Unknown",
      confidence: "UNKNOWN",
      evidence: [
        {
          kind: "missing-data",
          resourceId: fw.firewallPolicyId,
          description: "Regeln der Firewall Policy nicht lesbar oder leer",
        },
      ],
    };
  }
  if (family === "ipv6") {
    evidence.push({
      kind: "platform",
      description:
        "Azure Firewall IPv6 (Preview): nur Network Rules; Application-/DNAT-Regeln und IP Groups gelten nicht für IPv6",
    });
  }

  // 1. Network rules.
  let possible: string | undefined;
  for (const c of collections.filter((x) => x.type.includes("Filter"))) {
    for (const r of c.rules.filter((x) => x.ruleType === "NetworkRule")) {
      const sources = family === "ipv6" ? r.sources : addressList(ctx, r.sources, r.sourceIpGroupIds);
      const destinations =
        family === "ipv6" ? r.destinations : addressList(ctx, r.destinations, r.destinationIpGroupIds);
      if (!matchPort(r.destinationPorts, r.protocols, flow.protocol, flow.port)) continue;
      const s = matchAddress(sources, flow.source, false, tagResolver(ctx));
      const d =
        r.destinationFqdns.length > 0 && destinations.length === 0
          ? "unknown"
          : matchAddress(destinations, flow.destination, flow.internet, tagResolver(ctx));
      if (s === "no" || d === "no") continue;
      const label = `${c.group}/${c.collection}/${r.name}`;
      if (s === "unknown" || d === "unknown") {
        possible ??= label;
        continue;
      }
      return {
        access: c.action === "Deny" ? "Deny" : "Allow",
        rule: label,
        confidence: possible ? "POSSIBLE" : "CONFIRMED",
        evidence: [
          ...evidence,
          {
            kind: "rule",
            resourceId: fw.firewallPolicyId,
            description: `Network Rule ${label} (${c.action})`,
          },
        ],
      };
    }
  }

  // 2. Application rules (FQDN-based) – only for IPv4 and destination-independent verdicts.
  if (family === "ipv4" && flow.internet) {
    for (const c of collections.filter((x) => x.type.includes("Filter"))) {
      for (const r of c.rules.filter((x) => x.ruleType === "ApplicationRule")) {
        if (matchAddress(addressList(ctx, r.sources, r.sourceIpGroupIds), flow.source, false) === "no")
          continue;
        const label = `${c.group}/${c.collection}/${r.name}`;
        const wildcard = r.targetFqdns.includes("*") || r.destinationFqdns.includes("*");
        return {
          access: c.action === "Deny" ? "Deny" : "Allow",
          rule: label,
          confidence: wildcard ? "LIKELY" : "POSSIBLE",
          evidence: [
            ...evidence,
            {
              kind: "rule",
              resourceId: fw.firewallPolicyId,
              description: wildcard
                ? `Application Rule ${label} erlaubt beliebige FQDNs`
                : `Application Rule ${label}: Ergebnis hängt vom Ziel-FQDN ab (${r.targetFqdns.slice(0, 3).join(", ")}${r.targetFqdns.length > 3 ? ", …" : ""})`,
            },
          ],
        };
      }
    }
  }

  return {
    access: possible ? "Unknown" : "Deny",
    rule: possible,
    confidence: possible ? "POSSIBLE" : "LIKELY",
    evidence: [
      ...evidence,
      {
        kind: "rule",
        resourceId: fw.firewallPolicyId,
        description: possible
          ? `Regel ${possible} könnte greifen (Service Tag/FQDN nicht auflösbar)`
          : "Keine passende Regel – Azure Firewall verwirft standardmäßig",
      },
    ],
  };
}
