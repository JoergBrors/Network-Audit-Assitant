import type { RawInventory, RawResource } from "../../src/models/discovery.js";

/** Synthetic hub-and-spoke landscape in ARG row format (no real tenant data). */
export const TENANT = "11111111-1111-1111-1111-111111111111";
export const SUB_CONN = "22222222-2222-2222-2222-222222222222";
export const SUB_APP = "33333333-3333-3333-3333-333333333333";

const rg = (sub: string, name: string) => `/subscriptions/${sub}/resourceGroups/${name}`;
const net = (sub: string, group: string, type: string, name: string) =>
  `${rg(sub, group)}/providers/Microsoft.Network/${type}/${name}`;

export const HUB = net(SUB_CONN, "rg-hub", "virtualNetworks", "vnet-hub");
export const SPOKE = net(SUB_APP, "rg-app", "virtualNetworks", "vnet-spoke");
export const LONELY = net(SUB_APP, "rg-app", "virtualNetworks", "vnet-lonely");
export const FW = net(SUB_CONN, "rg-hub", "azureFirewalls", "afw-hub");
export const FW_POLICY = net(SUB_CONN, "rg-hub", "firewallPolicies", "afwp-hub");
export const VNG = net(SUB_CONN, "rg-hub", "virtualNetworkGateways", "vpngw-hub");
export const RT_SPOKE = net(SUB_APP, "rg-app", "routeTables", "rt-spoke");
export const NSG_SPOKE = net(SUB_APP, "rg-app", "networkSecurityGroups", "nsg-spoke");
export const NAT = net(SUB_CONN, "rg-hub", "natGateways", "nat-hub");
export const PIP_NAT = net(SUB_CONN, "rg-hub", "publicIPAddresses", "pip-nat");
export const PIP_VM = net(SUB_APP, "rg-app", "publicIPAddresses", "pip-vm6");
export const NIC_VM = net(SUB_APP, "rg-app", "networkInterfaces", "nic-vm1");
export const NIC_PE = net(SUB_APP, "rg-app", "networkInterfaces", "pe-sql.nic.abc");
export const PE = net(SUB_APP, "rg-app", "privateEndpoints", "pe-sql");
export const VM = `${rg(SUB_APP, "rg-app")}/providers/Microsoft.Compute/virtualMachines/vm1`;
export const SQL = `${rg(SUB_APP, "rg-data")}/providers/Microsoft.Sql/servers/sql1`;
export const FOREIGN_VNET = net(
  "44444444-4444-4444-4444-444444444444",
  "rg-x",
  "virtualNetworks",
  "vnet-foreign",
);
export const SNET_FW = `${HUB}/subnets/AzureFirewallSubnet`;
export const SNET_GW = `${HUB}/subnets/GatewaySubnet`;
export const SNET_HUB_NAT = `${HUB}/subnets/snet-egress`;
export const SNET_APP = `${SPOKE}/subnets/snet-app`;

const res = (
  id: string,
  type: string,
  properties: Record<string, unknown>,
  extra: Record<string, unknown> = {},
): RawResource => {
  const sub = /\/subscriptions\/([^/]+)/.exec(id)![1]!;
  return {
    id,
    name: id.split("/").pop()!,
    type,
    tenantId: TENANT,
    subscriptionId: sub,
    resourceGroup: /\/resourceGroups\/([^/]+)/.exec(id)![1]!.toLowerCase(),
    location: "westeurope",
    properties,
    ...extra,
  };
};

const subnet = (id: string, prefixes: string[], props: Record<string, unknown> = {}) => ({
  id,
  name: id.split("/").pop(),
  properties:
    prefixes.length === 1
      ? { addressPrefix: prefixes[0], ...props }
      : { addressPrefixes: prefixes, ...props },
});

const peering = (vnet: string, remote: string, space: string[], flags: Record<string, boolean>) => ({
  id: `${vnet}/virtualNetworkPeerings/to-${remote.split("/").pop()}`,
  name: `to-${remote.split("/").pop()}`,
  properties: {
    remoteVirtualNetwork: { id: remote },
    remoteVirtualNetworkAddressSpace: { addressPrefixes: space },
    peeringState: "Connected",
    peeringSyncLevel: "FullyInSync",
    allowVirtualNetworkAccess: true,
    allowForwardedTraffic: true,
    allowGatewayTransit: false,
    useRemoteGateways: false,
    ...flags,
  },
});

export function hubSpokeRaw(
  overrides: { spokeIpv6Route?: "Internet" | "Firewall" | "none" } = {},
): RawInventory {
  const ipv6Route = overrides.spokeIpv6Route ?? "Internet";
  const vnets: RawResource[] = [
    res(HUB, "microsoft.network/virtualnetworks", {
      addressSpace: { addressPrefixes: ["10.0.0.0/16", "fd00:10::/48"] },
      subnets: [
        subnet(SNET_FW, ["10.0.1.0/26", "fd00:10:0:1::/64"], {
          ipConfigurations: [{ id: `${FW}/azureFirewallIpConfigurations/ipconfig` }],
        }),
        subnet(SNET_GW, ["10.0.2.0/27"], { ipConfigurations: [{ id: `${VNG}/ipConfigurations/default` }] }),
        subnet(SNET_HUB_NAT, ["10.0.3.0/24"], { natGateway: { id: NAT } }),
      ],
      virtualNetworkPeerings: [
        peering(HUB, SPOKE, ["10.1.0.0/16", "fd00:11::/48"], { allowGatewayTransit: true }),
        peering(HUB, FOREIGN_VNET, ["10.9.0.0/16"], {}),
      ],
    }),
    res(SPOKE, "microsoft.network/virtualnetworks", {
      addressSpace: { addressPrefixes: ["10.1.0.0/16", "fd00:11::/48"] },
      subnets: [
        subnet(SNET_APP, ["10.1.1.0/24", "fd00:11:0:1::/64"], {
          networkSecurityGroup: { id: NSG_SPOKE },
          routeTable: { id: RT_SPOKE },
          defaultOutboundAccess: false,
          ipConfigurations: [
            { id: `${NIC_VM}/ipConfigurations/ipconfig1` },
            { id: `${NIC_PE}/ipConfigurations/privateEndpointIpConfig.1` },
          ],
          privateEndpoints: [{ id: PE }],
        }),
      ],
      virtualNetworkPeerings: [
        peering(SPOKE, HUB, ["10.0.0.0/16", "fd00:10::/48"], { useRemoteGateways: true }),
      ],
    }),
    res(LONELY, "microsoft.network/virtualnetworks", {
      addressSpace: { addressPrefixes: ["192.168.0.0/24"] },
      subnets: [],
    }),
  ];

  const routes: Record<string, unknown>[] = [
    {
      name: "default-v4",
      properties: {
        addressPrefix: "0.0.0.0/0",
        nextHopType: "VirtualAppliance",
        nextHopIpAddress: "10.0.1.4",
      },
    },
  ];
  if (ipv6Route === "Internet")
    routes.push({ name: "default-v6", properties: { addressPrefix: "::/0", nextHopType: "Internet" } });
  if (ipv6Route === "Firewall") {
    routes.push({
      name: "default-v6",
      properties: {
        addressPrefix: "::/0",
        nextHopType: "VirtualAppliance",
        nextHopIpAddress: "fd00:10:0:1::4",
      },
    });
  }
  routes.push({ name: "storage", properties: { addressPrefix: "Storage", nextHopType: "Internet" } });

  return {
    generatedAt: "2026-09-25T10:00:00.000Z",
    tenants: [{ tenantId: TENANT, displayName: "Contoso", accessible: true }],
    subscriptions: [
      {
        subscriptionId: SUB_CONN,
        displayName: "Connectivity",
        tenantId: TENANT,
        accessTenantId: TENANT,
        state: "Enabled",
        managedByTenantIds: [],
      },
      {
        subscriptionId: SUB_APP,
        displayName: "Application",
        tenantId: TENANT,
        accessTenantId: TENANT,
        state: "Enabled",
        managedByTenantIds: [],
      },
    ],
    resources: {
      "Q-ORG-01": [],
      "Q-NET-VNET": vnets,
      "Q-NET-RT": [
        res(RT_SPOKE, "microsoft.network/routetables", {
          disableBgpRoutePropagation: true,
          subnets: [{ id: SNET_APP }],
          routes: routes.map((r) => ({ id: `${RT_SPOKE}/routes/${String(r["name"])}`, ...r })),
        }),
      ],
      "Q-NET-NSG": [
        res(NSG_SPOKE, "microsoft.network/networksecuritygroups", {
          subnets: [{ id: SNET_APP }],
          securityRules: [
            {
              name: "allow-https-v6",
              properties: {
                priority: 100,
                direction: "Inbound",
                access: "Allow",
                protocol: "Tcp",
                sourceAddressPrefix: "::/0",
                destinationAddressPrefix: "*",
                destinationPortRange: "443",
                sourcePortRange: "*",
              },
            },
            {
              name: "allow-lb",
              properties: {
                priority: 200,
                direction: "Inbound",
                access: "Allow",
                protocol: "*",
                sourceAddressPrefix: "AzureLoadBalancer",
                destinationAddressPrefix: "*",
                destinationPortRange: "*",
                sourcePortRange: "*",
              },
            },
          ],
          defaultSecurityRules: [
            {
              name: "DenyAllInBound",
              properties: {
                priority: 65500,
                direction: "Inbound",
                access: "Deny",
                protocol: "*",
                sourceAddressPrefix: "*",
                destinationAddressPrefix: "*",
                destinationPortRange: "*",
                sourcePortRange: "*",
              },
            },
          ],
        }),
      ],
      "Q-NET-NIC": [
        res(NIC_VM, "microsoft.network/networkinterfaces", {
          virtualMachine: { id: VM },
          enableIPForwarding: false,
          defaultOutboundConnectivityEnabled: false,
          ipConfigurations: [
            {
              name: "ipconfig1",
              properties: {
                primary: true,
                privateIPAddress: "10.1.1.4",
                privateIPAddressVersion: "IPv4",
                subnet: { id: SNET_APP },
              },
            },
            {
              name: "ipconfig6",
              properties: {
                privateIPAddress: "fd00:11:0:1::4",
                privateIPAddressVersion: "IPv6",
                subnet: { id: SNET_APP },
                publicIPAddress: { id: PIP_VM },
              },
            },
          ],
        }),
        res(NIC_PE, "microsoft.network/networkinterfaces", {
          privateEndpoint: { id: PE },
          ipConfigurations: [
            { name: "pe", properties: { privateIPAddress: "10.1.1.10", subnet: { id: SNET_APP } } },
          ],
        }),
      ],
      "Q-NET-PIP": [
        res(
          PIP_NAT,
          "microsoft.network/publicipaddresses",
          { ipAddress: "198.51.100.10", publicIPAddressVersion: "IPv4", natGateway: { id: NAT } },
          { sku: { name: "Standard" } },
        ),
        res(
          PIP_VM,
          "microsoft.network/publicipaddresses",
          {
            ipAddress: "2001:db8::10",
            publicIPAddressVersion: "IPv6",
            ipConfiguration: { id: `${NIC_VM}/ipConfigurations/ipconfig6` },
          },
          { sku: { name: "Standard" } },
        ),
      ],
      "Q-NET-NAT": [
        res(
          NAT,
          "microsoft.network/natgateways",
          { subnets: [{ id: SNET_HUB_NAT }], publicIpAddresses: [{ id: PIP_NAT }] },
          { sku: { name: "Standard" } },
        ),
      ],
      "Q-SEC-FW": [
        res(FW, "microsoft.network/azurefirewalls", {
          sku: { name: "AZFW_VNet", tier: "Premium" },
          firewallPolicy: { id: FW_POLICY },
          ipConfigurations: [
            { name: "ipconfig", properties: { privateIPAddress: "10.0.1.4", subnet: { id: SNET_FW } } },
          ],
        }),
      ],
      "Q-SEC-FWP": [
        res(FW_POLICY, "microsoft.network/firewallpolicies", {
          firewalls: [{ id: FW }],
          ruleCollectionGroups: [{ id: `${FW_POLICY}/ruleCollectionGroups/rcg-net` }],
        }),
      ],
      "Q-SEC-FWRCG": [
        res(
          `${FW_POLICY}/ruleCollectionGroups/rcg-net`,
          "microsoft.network/firewallpolicies/rulecollectiongroups",
          {
            priority: 200,
            ruleCollections: [
              {
                name: "allow-web",
                ruleCollectionType: "FirewallPolicyFilterRuleCollection",
                priority: 100,
                action: { type: "Allow" },
                rules: [
                  {
                    name: "web",
                    ruleType: "NetworkRule",
                    sourceAddresses: ["10.1.0.0/16"],
                    destinationAddresses: ["*"],
                    destinationPorts: ["443"],
                    ipProtocols: ["TCP"],
                    ipv6Rule: false,
                  },
                ],
              },
            ],
          },
        ),
      ],
      "Q-HYB-GW": [
        res(VNG, "microsoft.network/virtualnetworkgateways", {
          gatewayType: "Vpn",
          vpnType: "RouteBased",
          sku: { name: "VpnGw2AZ" },
          enableBgp: true,
          ipConfigurations: [{ name: "default", properties: { subnet: { id: SNET_GW } } }],
        }),
      ],
      "Q-PE": [
        res(PE, "microsoft.network/privateendpoints", {
          subnet: { id: SNET_APP },
          networkInterfaces: [{ id: NIC_PE }],
          privateLinkServiceConnections: [
            {
              name: "c",
              properties: {
                privateLinkServiceId: SQL,
                groupIds: ["sqlServer"],
                privateLinkServiceConnectionState: { status: "Approved" },
              },
            },
          ],
        }),
      ],
      "Q-CMP-VM": [
        {
          id: VM,
          name: "vm1",
          type: "microsoft.compute/virtualmachines",
          subscriptionId: SUB_APP,
          resourceGroup: "rg-app",
          location: "westeurope",
          nics: [{ id: NIC_VM }],
          vmSize: "Standard_D2s_v5",
          imageReference: { publisher: "MicrosoftWindowsServer", offer: "WindowsServer", sku: "2022" },
          powerState: "PowerState/running",
        },
      ],
      "Q-NET-ALL": [
        res(net(SUB_CONN, "rg-hub", "brandNewThings", "x1"), "microsoft.network/brandnewthings", {
          subnet: { id: SNET_HUB_NAT },
        }),
      ],
    },
    queryStats: [],
    warnings: [],
    quality: {
      tenants: { total: 1, readable: 1 },
      subscriptions: { total: 2, readable: 2 },
      networkResources: 20,
      argQueries: { executed: 10, pages: 10, truncated: 0, failed: 0 },
      armEnrichment: { attempted: 0, successful: 0, unavailable: 0 },
      overallConfidence: "HIGH",
    },
  };
}
