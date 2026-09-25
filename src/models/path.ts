import type { IpFamily } from "../addressing/ip.js";

/** How certain a statement is (ARCHITECTURE.md § 9.1). Missing data never yields CONFIRMED. */
export type Confidence = "CONFIRMED" | "LIKELY" | "POSSIBLE" | "UNKNOWN";

export interface Evidence {
  kind: "property" | "route" | "rule" | "relationship" | "heuristic" | "missing-data" | "platform";
  resourceId?: string | undefined;
  description: string;
}

export type RouteSource = "udr" | "system" | "peering" | "gateway" | "vwan";

export interface EffectiveRoute {
  prefix: string;
  family: IpFamily;
  nextHopType:
    | "VnetLocal"
    | "VNetPeering"
    | "ConnectedGroup"
    | "VirtualHub"
    | "VirtualNetworkGateway"
    | "Internet"
    | "VirtualAppliance"
    | "None";
  nextHopIpAddress?: string | undefined;
  /** Equal-cost multipath: all next hop IPs (VirtualApplianceEcmp). */
  nextHopIpAddresses?: string[] | undefined;
  /** UDR defined with a service tag instead of an explicit prefix. */
  serviceTag?: string | undefined;
  /** Resource the next hop points to (remote VNet, gateway, appliance), if known. */
  nextHopResourceId?: string | undefined;
  source: RouteSource;
  /** Route resource (UDR) or originating resource (peering, gateway connection). */
  originId?: string | undefined;
  confidence: Confidence;
  note?: string | undefined;
}

export type PathStatus = "ALLOWED" | "BLOCKED" | "UNKNOWN" | "POTENTIAL_BYPASS";

export type HopType =
  | "source"
  | "subnet"
  | "route"
  | "peering"
  | "firewall"
  | "nva"
  | "loadBalancer"
  | "gateway"
  | "virtualHub"
  | "natGateway"
  | "publicIp"
  | "internet"
  | "onPremises"
  | "destination"
  | "drop";

export interface PathHop {
  index: number;
  type: HopType;
  /** Graph node representing the hop (for highlighting). */
  nodeId?: string | undefined;
  label: string;
  /** Why the packet takes this hop, e.g. "UDR ::/0 → VirtualAppliance fd00::4". */
  reason: string;
  route?: EffectiveRoute | undefined;
  decision?:
    | {
        control: "nsg" | "firewall" | "avnm";
        resourceId: string;
        direction?: "Inbound" | "Outbound";
        access: "Allow" | "Deny" | "AlwaysAllow" | "Unknown";
        rule?: string | undefined;
      }
    | undefined;
  confidence: Confidence;
  evidence: Evidence[];
}

export type EgressMechanism =
  | "firewall"
  | "nva"
  | "natGateway"
  | "instancePublicIp"
  | "loadBalancerOutbound"
  | "defaultOutbound"
  | "gateway"
  | "none"
  | "unknown";

export interface EgressInfo {
  family: IpFamily;
  mechanism: EgressMechanism;
  /** True when a central security control (firewall/NVA) inspects the traffic. */
  controlled: boolean;
  publicIps: string[];
  resourceId?: string | undefined;
  confidence: Confidence;
  evidence: Evidence[];
}

export type PathDestination =
  { kind: "internet" } | { kind: "ip"; address: string } | { kind: "resource"; id: string };

export interface PathQuery {
  /** Subnet, NIC, VM, VM scale set or private endpoint. */
  sourceId: string;
  destination: PathDestination;
  family: IpFamily;
  protocol?: "Tcp" | "Udp" | "Icmp" | "*" | undefined;
  port?: number | undefined;
}

export interface PathResult {
  query: PathQuery;
  status: PathStatus;
  confidence: Confidence;
  summary: string;
  hops: PathHop[];
  egress?: EgressInfo | undefined;
  /** Security controls traversed (firewall/NVA IDs). */
  securityControls: string[];
  sourceAddress?: string | undefined;
  destinationAddress?: string | undefined;
  /** Source or destination has no address of the family (path not applicable, not a failure). */
  notApplicable?: boolean | undefined;
}

export interface PathComparison {
  ipv4: PathResult;
  ipv6: PathResult;
  /** Human-readable differences, most important first. */
  differences: string[];
  architectureGap?: string | undefined;
}

const RANK: Record<Confidence, number> = { CONFIRMED: 3, LIKELY: 2, POSSIBLE: 1, UNKNOWN: 0 };

export function weakest(...values: Confidence[]): Confidence {
  return values.reduce<Confidence>((a, b) => (RANK[b] < RANK[a] ? b : a), "CONFIRMED");
}
