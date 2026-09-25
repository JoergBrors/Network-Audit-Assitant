/**
 * Azure Resource Graph query catalog. Specification: RESOURCE-GRAPH-QUERIES.md.
 * Every query is read-only KQL, ordered by id for stable paging.
 */

export type ArgTable =
  "resources" | "resourcecontainers" | "networkresources" | "dnsresources" | "computeresources";

export interface ArgQueryDefinition {
  id: string;
  /** Bump when the KQL changes so cached results are invalidated. */
  version: number;
  table: ArgTable;
  scope: "subscriptions" | "tenantRootManagementGroup";
  description: string;
  kql: string;
  /** Resource types explicitly covered (lowercase); used to build the unclassified catch-all. */
  types: readonly string[];
}

const BASE_PROJECTION =
  "project id, name, type, tenantId, subscriptionId, resourceGroup, location, kind, sku, zones, tags, properties";

function inList(types: readonly string[]): string {
  return types.map((t) => `'${t}'`).join(", ");
}

function typeQuery(
  id: string,
  table: ArgTable,
  description: string,
  types: readonly string[],
  projection = BASE_PROJECTION,
): ArgQueryDefinition {
  return {
    id,
    version: 1,
    table,
    scope: "subscriptions",
    description,
    types,
    kql: `${table}\n| where type in~ (${inList(types)})\n| ${projection}\n| order by id asc`,
  };
}

const n = (t: string): string => `microsoft.network/${t}`;

export const ORG_SUBSCRIPTIONS: ArgQueryDefinition = {
  id: "Q-ORG-01",
  version: 1,
  table: "resourcecontainers",
  scope: "subscriptions",
  description: "Subscriptions and resource groups incl. management group chain and Lighthouse delegation",
  types: ["microsoft.resources/subscriptions", "microsoft.resources/subscriptions/resourcegroups"],
  kql: `resourcecontainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, tenantId, subscriptionId, resourceGroup, location, tags,
          state = tostring(properties.state),
          mgChain = properties.managementGroupAncestorsChain,
          managedByTenants = properties.managedByTenants
| order by id asc`,
};

export const ORG_MANAGEMENT_GROUPS: ArgQueryDefinition = {
  id: "Q-ORG-02",
  version: 1,
  table: "resourcecontainers",
  scope: "tenantRootManagementGroup",
  description: "Management group hierarchy (requires management group scope)",
  types: ["microsoft.management/managementgroups"],
  kql: `resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project id, name, type, tenantId, displayName = tostring(properties.displayName),
          parent = tostring(properties.details.parent.id)
| order by id asc`,
};

export const NETWORK_QUERIES: readonly ArgQueryDefinition[] = [
  typeQuery("Q-NET-VNET", "resources", "Virtual networks incl. inline subnets and peerings", [
    n("virtualnetworks"),
  ]),
  typeQuery("Q-NET-RT", "resources", "Route tables incl. routes", [n("routetables")]),
  typeQuery("Q-NET-NSG", "resources", "Network security groups and application security groups", [
    n("networksecuritygroups"),
    n("applicationsecuritygroups"),
  ]),
  typeQuery("Q-NET-NIC", "resources", "Network interfaces", [n("networkinterfaces")]),
  typeQuery("Q-NET-VMSSNIC", "computeresources", "VM scale set (uniform) network interfaces", [
    "microsoft.compute/virtualmachinescalesets/virtualmachines/networkinterfaces",
  ]),
  typeQuery("Q-NET-PIP", "resources", "Public IP addresses", [n("publicipaddresses")]),
  typeQuery("Q-NET-PIPP", "resources", "Public and custom IP prefixes", [
    n("publicipprefixes"),
    n("customipprefixes"),
  ]),
  typeQuery("Q-NET-NAT", "resources", "NAT gateways", [n("natgateways")]),
  typeQuery("Q-NET-SVCGW", "resources", "Service gateways", [n("servicegateways")]),
  typeQuery("Q-SEC-FW", "resources", "Azure Firewalls", [n("azurefirewalls")]),
  typeQuery("Q-SEC-FWP", "resources", "Firewall policies and IP groups", [
    n("firewallpolicies"),
    n("ipgroups"),
  ]),
  typeQuery("Q-SEC-FWRCG", "networkresources", "Firewall policy rule collection groups incl. rules", [
    n("firewallpolicies/rulecollectiongroups"),
  ]),
  typeQuery("Q-SEC-WAF", "resources", "WAF policies", [
    n("applicationgatewaywebapplicationfirewallpolicies"),
    n("frontdoorwebapplicationfirewallpolicies"),
    "microsoft.cdn/cdnwebapplicationfirewallpolicies",
  ]),
  typeQuery("Q-SEC-DDOS", "resources", "DDoS protection plans", [n("ddosprotectionplans")]),
  typeQuery("Q-SEC-AVNM", "networkresources", "Azure Virtual Network Manager effective configuration", [
    n("effectivesecurityadminrules"),
    n("effectiveconnectivityconfigurations"),
    n("networkgroupmemberships"),
    n("virtualnetworks/subnets/effectiveroutingrules"),
    n("networkmanagerconnections"),
  ]),
  typeQuery("Q-SEC-NSP", "networkresources", "Network security perimeters", [
    n("networksecurityperimeters/profiles"),
    n("networksecurityperimeters/profiles/accessrules"),
    n("networksecurityperimeters/resourceassociations"),
  ]),
  typeQuery("Q-LB", "resources", "Load balancers", [n("loadbalancers")]),
  typeQuery("Q-AGW", "resources", "Application gateways", [n("applicationgateways")]),
  typeQuery("Q-FD", "resources", "Front Door (Standard/Premium and classic)", [
    "microsoft.cdn/profiles",
    "microsoft.cdn/profiles/afdendpoints",
    n("frontdoors"),
  ]),
  typeQuery("Q-TM", "resources", "Traffic Manager profiles", [n("trafficmanagerprofiles")]),
  typeQuery("Q-BAS", "resources", "Bastion hosts", [n("bastionhosts")]),
  typeQuery("Q-HYB-GW", "resources", "VPN/ER virtual network gateways, local network gateways, connections", [
    n("virtualnetworkgateways"),
    n("localnetworkgateways"),
    n("connections"),
  ]),
  typeQuery("Q-HYB-ER", "resources", "ExpressRoute", [
    n("expressroutecircuits"),
    n("expressroutegateways"),
    n("expressrouteports"),
    n("expressroutecrossconnections"),
    n("routefilters"),
  ]),
  typeQuery("Q-VWAN", "resources", "Virtual WAN, hubs, Route Server, BGP connections", [
    n("virtualwans"),
    n("virtualhubs"),
    n("virtualhubs/bgpconnections"),
    n("virtualhubs/ipconfigurations"),
    n("vpngateways"),
    n("vpnsites"),
    n("p2svpngateways"),
    n("vpnserverconfigurations"),
    n("virtualrouters"),
    n("securitypartnerproviders"),
  ]),
  typeQuery("Q-NVA", "resources", "Managed network virtual appliances", [n("networkvirtualappliances")]),
  typeQuery("Q-PE", "resources", "Private endpoints and private link services", [
    n("privateendpoints"),
    n("privatelinkservices"),
  ]),
  typeQuery("Q-DNS-ZONES", "resources", "Private DNS zones, VNet links, DNS resolvers and rulesets", [
    n("privatednszones"),
    n("privatednszones/virtualnetworklinks"),
    n("dnszones"),
    n("dnsresolvers"),
    n("dnsresolvers/inboundendpoints"),
    n("dnsresolvers/outboundendpoints"),
    n("dnsforwardingrulesets"),
    n("dnsresolverpolicies"),
    n("dnsresolverpolicies/virtualnetworklinks"),
    n("dnssecuritypolicies"),
  ]),
  typeQuery(
    "Q-DNS-REC",
    "dnsresources",
    "Private DNS record sets and forwarding rules",
    [
      n("privatednszones/a"),
      n("privatednszones/aaaa"),
      n("privatednszones/cname"),
      n("privatednszones/ptr"),
      n("privatednszones/srv"),
      n("dnsforwardingrulesets/forwardingrules"),
      n("dnsforwardingrulesets/virtualnetworklinks"),
    ],
    "project id, name, type, tenantId, subscriptionId, resourceGroup, properties",
  ),
  typeQuery(
    "Q-CMP-VM",
    "resources",
    "Virtual machines (network-relevant fields only; osProfile is never projected)",
    ["microsoft.compute/virtualmachines"],
    `project id, name, type, tenantId, subscriptionId, resourceGroup, location, zones, tags,
          vmSize = tostring(properties.hardwareProfile.vmSize),
          nics = properties.networkProfile.networkInterfaces,
          imageReference = properties.storageProfile.imageReference,
          plan,
          powerState = tostring(properties.extended.instanceView.powerState.code)`,
  ),
  typeQuery(
    "Q-CMP-VMSS",
    "resources",
    "VM scale sets (network profile only)",
    ["microsoft.compute/virtualmachinescalesets"],
    `project id, name, type, tenantId, subscriptionId, resourceGroup, location, zones, tags, sku,
          orchestrationMode = tostring(properties.orchestrationMode),
          networkProfile = properties.virtualMachineProfile.networkProfile`,
  ),
  typeQuery("Q-MON", "resources", "Network Watcher, flow logs, connection monitors", [
    n("networkwatchers"),
    n("networkwatchers/flowlogs"),
    n("networkwatchers/connectionmonitors"),
  ]),
];

function unclassifiedQuery(id: string, table: "resources" | "networkresources"): ArgQueryDefinition {
  const known = [
    ...new Set(NETWORK_QUERIES.flatMap((q) => q.types).filter((t) => t.startsWith("microsoft.network/"))),
  ];
  return {
    id,
    version: 1,
    table,
    scope: "subscriptions",
    description: `All other Microsoft.Network resource types in ${table} (unclassifiedNetworkResources)`,
    types: [],
    kql: `${table}\n| where type startswith 'microsoft.network/'\n| where type !in~ (${inList(known)})\n| ${BASE_PROJECTION}\n| order by id asc`,
  };
}

export const UNCLASSIFIED_QUERIES: readonly ArgQueryDefinition[] = [
  unclassifiedQuery("Q-NET-ALL", "resources"),
  unclassifiedQuery("Q-NET-ALL-NR", "networkresources"),
];

/** All subscription-scoped queries executed by a standard discovery run. */
export const DISCOVERY_QUERIES: readonly ArgQueryDefinition[] = [
  ORG_SUBSCRIPTIONS,
  ...NETWORK_QUERIES,
  ...UNCLASSIFIED_QUERIES,
];
