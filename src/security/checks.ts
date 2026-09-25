import type { NicEntity, SubnetEntity } from "../models/network.js";
import { weakest, type PathHop } from "../models/path.js";
import type { RoutingContext } from "../routing/context.js";
import { evaluateAdminRules, evaluateNsg, type FlowTuple } from "./nsg.js";

/** Subnets to which AVNM security admin rules are not applied (Microsoft Learn: concept-security-admins). */
const ADMIN_EXEMPT_SUBNETS =
  /^(azurefirewallsubnet|azurefirewallmanagementsubnet|gatewaysubnet|azurebastionsubnet|routeserversubnet)$/i;

export interface SecurityCheck {
  /** Set when the flow is denied; the hop describes the denying control. */
  blocked?: Omit<PathHop, "index"> | undefined;
  /** Informational hops (AVNM decisions) to show in the path. */
  hops: Omit<PathHop, "index">[];
  uncertain: boolean;
}

const nameOf = (id: string) => id.split("/").pop() ?? id;

/**
 * Security evaluation at one end of a flow: AVNM security admin rules first (Deny stops,
 * AlwaysAllow skips NSGs, Allow continues), then NSGs – outbound NIC → subnet, inbound subnet → NIC.
 */
export function checkSecurity(
  ctx: RoutingContext,
  direction: "Inbound" | "Outbound",
  subnet: SubnetEntity,
  nic: NicEntity | undefined,
  flow: FlowTuple,
): SecurityCheck {
  const result: SecurityCheck = { hops: [], uncertain: false };
  const vnetId = subnet.vnetId;
  const exempt =
    ADMIN_EXEMPT_SUBNETS.test(subnet.name) ||
    subnet.connectedResourceIds.some((r) => r.includes("/applicationgateways/"));
  const adminConfigs = ctx.inv.avnm?.vnetAdminConfigurations[vnetId];
  if (adminConfigs && adminConfigs.length > 0 && !exempt) {
    const rules = ctx.adminRulesByVnet.get(vnetId) ?? [];
    if (rules.length === 0) {
      result.uncertain = true;
      result.hops.push({
        type: "subnet",
        nodeId: vnetId,
        label: "AVNM Security Admin",
        reason: "Security-Admin-Konfiguration wirksam, Regeln aber nicht lesbar",
        confidence: "UNKNOWN",
        evidence: [
          {
            kind: "missing-data",
            resourceId: vnetId,
            description: `Konfigurationen: ${adminConfigs.map(nameOf).join(", ")}`,
          },
        ],
      });
    } else {
      const d = evaluateAdminRules(rules, direction, flow);
      if (d) {
        const confidence = weakest(d.confidence, "LIKELY");
        const hop: Omit<PathHop, "index"> = {
          type: d.access === "Deny" ? "drop" : "subnet",
          nodeId: vnetId,
          label: "AVNM Security Admin",
          reason: `Security Admin Rule ${d.rule}: ${d.access}${d.access === "AlwaysAllow" ? " (NSGs werden übersprungen)" : d.access === "Allow" ? " (weiter mit NSG)" : ""}`,
          decision: { control: "avnm", resourceId: vnetId, direction, access: d.access, rule: d.rule },
          confidence,
          evidence: [
            {
              kind: "rule",
              resourceId: vnetId,
              description: `AVNM-Regel ${d.rule} (Priorität ${d.priority}), wird vor NSGs ausgewertet`,
            },
          ],
        };
        if (d.confidence !== "CONFIRMED") result.uncertain = true;
        if (d.access === "Deny") return { ...result, blocked: hop };
        result.hops.push(hop);
        if (d.access === "AlwaysAllow") return result;
      }
    }
  }

  const order: [string | undefined, string][] =
    direction === "Outbound"
      ? [
          [nic?.nsgId, "NIC"],
          [subnet.nsgId, "Subnet"],
        ]
      : [
          [subnet.nsgId, "Subnet"],
          [nic?.nsgId, "NIC"],
        ];
  for (const [nsgId, scope] of order) {
    if (!nsgId) continue;
    const d = evaluateNsg(ctx.nsgs.get(nsgId), direction, flow);
    if (!d) continue;
    if (d.confidence !== "CONFIRMED") result.uncertain = true;
    if (d.access === "Deny") {
      result.blocked = {
        type: "drop",
        nodeId: nsgId,
        label: nameOf(nsgId),
        reason: `NSG (${scope}) verweigert ${direction === "Inbound" ? "eingehend" : "ausgehend"}: ${d.rule}`,
        decision: { control: "nsg", resourceId: nsgId, direction, access: "Deny", rule: d.rule },
        confidence: d.confidence,
        evidence: [
          {
            kind: "rule",
            resourceId: nsgId,
            description: `Regel ${d.rule} (Priorität ${d.priority})${d.note ? ` – ${d.note}` : ""}`,
          },
        ],
      };
      return result;
    }
  }
  return result;
}
