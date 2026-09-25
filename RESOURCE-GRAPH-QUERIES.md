# RESOURCE-GRAPH-QUERIES — Query-Katalog

Stand 2026-09-25 · ARG REST API `2024-04-01` (`@azure/arm-resourcegraph@5`) · Implementierung: `src/azure/resourceGraph/queries.ts` (dieses Dokument ist die Spezifikation, der Code ist die Quelle der Wahrheit für den exakten KQL-Text).

## 1. Verifikationsgrundlage

| Quelle | Inhalt |
| --- | --- |
| Microsoft Learn: *Azure Resource Graph table and resource type reference* (abgerufen 2026-09-25) | Welche Typen in welcher ARG-Tabelle liegen |
| Live-Prüfung (read-only, nur `summarize count()` / `bag_keys()`) gegen einen realen Tenant | Tatsächlich vorhandene Properties je Typ |
| `@azure/arm-network@39` (API `2026-01-01`) Modelle | Property-Namen und Enums |

**Tabellen, die das Tool nutzt:** `resources`, `resourcecontainers`, `networkresources`, `dnsresources`, `computeresources`.

## 2. Allgemeine Regeln für alle Queries

- **Scope:** Subscription-Batches (Default 200 IDs, konfigurierbar) je Tenant. Ausnahme Q-ORG-02 mit Management-Group-Scope (Root-MG-ID = Tenant-ID).
- **Paging:** `options.top = 1000`, Folgeseiten per `skipToken`. Jede Query endet mit `order by id asc` für stabiles Paging.
- **Adaptive Seitengröße:** Scheitert eine Seite wegen Payload-Größe, wird `top` halbiert (bis 50) und die Seite wiederholt.
- **Truncation:** `resultTruncated == "true"` ohne `skipToken` → Batch nach Subscriptions aufteilen, Warnung `Truncated`.
- **Standardprojektion** (`$base`): `id, name, type, tenantId, subscriptionId, resourceGroup, location, kind, sku, zones, tags, properties`. Ausnahmen sind unten vermerkt (VMs: explizite Projektion, damit z. B. `osProfile` nie geladen wird).
- **Groß-/Kleinschreibung:** Typvergleiche immer mit `=~` / `in~`; IDs werden in der Normalisierung lowercase gesetzt.
- **Leere Properties:** ARG lässt nicht gesetzte Properties weg. Normalizer müssen fehlende Felder als „nicht gesetzt“ behandeln, nicht als Fehler (z. B. `subnet.addressPrefix` vs. `addressPrefixes`).
- **Keine Secrets:** ARG liefert für `connections` keinen `sharedKey` und für Application Gateways keine Zertifikats-`data`. Der Normalizer übernimmt solche Felder trotzdem nie (Blocklist).

Notation unten: `$base` = Standardprojektion, `$order` = `| order by id asc`.

---

## 3. Organisation

### Q-ORG-01 Subscriptions & Resource Groups
```kusto
resourcecontainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, tenantId, subscriptionId, resourceGroup, location, tags,
          state = tostring(properties.state),
          mgChain = properties.managementGroupAncestorsChain,
          managedByTenants = properties.managedByTenants
| order by id asc
```
Liefert u. a. `managementGroupAncestorsChain` (MG-Pfad je Subscription, live verifiziert) und `managedByTenants` (Lighthouse).

### Q-ORG-02 Management Groups (Scope: `managementGroups: [<tenantId>]`)
```kusto
resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project id, name, tenantId, displayName = tostring(properties.displayName),
          parent = tostring(properties.details.parent.id)
| order by id asc
```
Live verifiziert: liefert Ergebnisse nur mit Management-Group-Scope. Fehlt der Zugriff, entsteht die Warnung `InsufficientPermissions` und die MG-Hierarchie wird aus `mgChain` (Q-ORG-01) rekonstruiert, soweit möglich.

---

## 4. Kern-Netzwerk

| ID | Tabelle | Typen | Inline-Daten (verifiziert ✔ / laut API-Modell ○) |
| --- | --- | --- | --- |
| Q-NET-VNET | resources | `microsoft.network/virtualnetworks` | ✔ `addressSpace`, `dhcpOptions.dnsServers`, `enableDdosProtection`, `ddosProtectionPlan`, `privateEndpointVNetPolicies`, `subnets[]` (inkl. `addressPrefix(es)`, `networkSecurityGroup`, `routeTable`, `natGateway`, `delegations`, `serviceEndpoints`, `privateEndpointNetworkPolicies`, `privateLinkServiceNetworkPolicies`, `ipConfigurations[]`), `virtualNetworkPeerings[]` (inkl. `remoteVirtualNetwork`, `remoteAddressSpace`, `remoteVirtualNetworkAddressSpace`, `allow*`, `useRemoteGateways`, `peeringState`, `peeringSyncLevel`, `peerCompleteVnets`, `remoteGateways`); ○ `encryption`, `flowTimeoutInMinutes`, `subnets[].defaultOutboundAccess`, `localSubnetNames`/`remoteSubnetNames` |
| Q-NET-RT | resources | `routetables` | ✔ `routes[]` (`addressPrefix`, `nextHopType`, `nextHopIpAddress`), `subnets[]`, `disableBgpRoutePropagation` |
| Q-NET-NSG | resources | `networksecuritygroups`, `applicationsecuritygroups` | ✔ `securityRules[]`, `defaultSecurityRules[]`, `subnets[]`, `networkInterfaces[]` |
| Q-NET-NIC | resources | `networkinterfaces` | ✔ `defaultOutboundConnectivityEnabled` (zeigt, ob die NIC tatsächlich Default Outbound Access nutzt; wichtig für Egress-Analyse), `enableIPForwarding`, `enableAcceleratedNetworking`, `virtualMachine`, `networkSecurityGroup`, `ipConfigurations[]`; ○ in `ipConfigurations[]` (`privateIPAddress`, `privateIPAddressVersion`, `subnet`, `publicIPAddress`, `loadBalancerBackendAddressPools`, `applicationSecurityGroups`, `primary`), `enableIPForwarding`, `enableAcceleratedNetworking`, `virtualMachine`, `networkSecurityGroup`, `privateEndpoint` |
| Q-NET-VMSSNIC | **computeresources** | `microsoft.compute/virtualmachinescalesets/virtualmachines/networkinterfaces` | ✔ Typ vorhanden (VMSS-Uniform-NICs); ersetzt den ursprünglich geplanten ARM-Fallback |
| Q-NET-PIP | resources | `publicipaddresses` | ○ `ipAddress`, `publicIPAddressVersion`, `publicIPAllocationMethod`, `ipConfiguration`, `natGateway`, `publicIPPrefix`, `sku.name/tier`, `dnsSettings` |
| Q-NET-PIPP | resources | `publicipprefixes`, `customipprefixes` | ○ `ipPrefix`, `prefixLength`, `publicIPAddressVersion`, `publicIPAddresses[]`, `natGateway` |
| Q-NET-NAT | resources | `natgateways` | ✔ `sku.name` (`Standard`/`StandardV2`), `subnets[]`, `publicIpAddresses[]`, `idleTimeoutInMinutes`; ○ `publicIpPrefixes[]`, `sourceVirtualNetwork` |
| Q-NET-SVCGW | resources | `servicegateways` | Neuer Typ (Subnet-Property `serviceGateway`); zunächst Typ + Beziehungen |

KQL-Muster (für alle Zeilen oben identisch, nur die Typliste unterscheidet sich):
```kusto
resources
| where type in~ (<typliste>)
| project $base
| order by id asc
```

## 5. Security-Kontrollpunkte

| ID | Tabelle | Typen | Hinweise |
| --- | --- | --- | --- |
| Q-SEC-FW | resources | `azurefirewalls` | ✔ `sku` (`AZFW_VNet`/`AZFW_Hub`, `tier`), `ipConfigurations`, `firewallPolicy`, `additionalProperties` (u. a. DNS-Proxy bei Classic), `threatIntelMode`, `applicationRuleCollections`, `networkRuleCollections`, `natRuleCollections`; ○ `managementIpConfiguration`, `hubIPAddresses` (Secured Hub), `virtualHub`; `zones` |
| Q-SEC-FWP | resources | `firewallpolicies`, `ipgroups` | ✔ `sku`, `threatIntelMode`, `firewalls`, `ruleCollectionGroups` (IDs), `childPolicies`, `insights`; ○ `basePolicy`, `dnsSettings`, `explicitProxy`, `intrusionDetection`, `transportSecurity`; IP Groups: `ipAddresses[]` |
| Q-SEC-FWRCG | **networkresources** | `microsoft.network/firewallpolicies/rulecollectiongroups` | ✔ `priority`, `ruleCollections[]` (`name`, `ruleCollectionType`, `priority`, `action`, `rules[]` mit `ruleType`, `sourceAddresses`, `destinationAddresses`, `sourceIpGroups`, `destinationIpGroups`, `destinationPorts`, `destinationFqdns`, `ipProtocols`, **`ipv6Rule`**). Plausibilitätsprüfung: Die RCG-IDs aus `firewallpolicies.properties.ruleCollectionGroups` müssen alle gefunden werden, sonst ARM-Fallback E-FW-01. |
| Q-SEC-WAF | resources | `applicationgatewaywebapplicationfirewallpolicies`, `frontdoorwebapplicationfirewallpolicies`, `microsoft.cdn/cdnwebapplicationfirewallpolicies` | Policy-Modus, verknüpfte Ressourcen |
| Q-SEC-DDOS | resources | `ddosprotectionplans` | VNet-Zuordnung |
| Q-SEC-AVNM | **networkresources** | `effectivesecurityadminrules`, `effectiveconnectivityconfigurations`, `networkgroupmemberships`, `virtualnetworks/subnets/effectiveroutingrules`, `networkmanagerconnections` | **Azure Virtual Network Manager**: Security Admin Rules werden *vor* NSGs ausgewertet und können Traffic unabhängig von NSGs erlauben oder blockieren; Connectivity Configurations (Mesh/Hub-Spoke) erzeugen Konnektivität **ohne** sichtbare VNet-Peerings; Routing Configurations erzeugen UDRs. Pflicht für eine korrekte Bypass-Analyse. |
| Q-SEC-NSP | networkresources | `networksecurityperimeters/*` | Nur Inventar (PaaS-Perimeter), Beziehungen zu PEs |

Die AVNM-Typen in `networkresources` sind in der Tabellenreferenz dokumentiert, im Test-Tenant aber nicht vorhanden. Die Property-Form wird beim ersten Treffer über die Verifikationsabfrage (§ 10) geprüft. Bis dahin normalisiert der Normalizer sie defensiv und kennzeichnet sie mit Konfidenz `LIKELY`.

## 6. Load Balancing, Ingress, Edge

| ID | Tabelle | Typen | Hinweise |
| --- | --- | --- | --- |
| Q-LB | resources | `loadbalancers` | ○ `frontendIPConfigurations`, `backendAddressPools`, `probes`, `loadBalancingRules`, `inboundNatRules`, `outboundRules`, `sku` |
| Q-AGW | resources | `applicationgateways` | ○ `frontendIPConfigurations`, `frontendPorts`, `httpListeners`, `backendAddressPools`, `backendHttpSettingsCollection`, `requestRoutingRules`, `firewallPolicy`, `webApplicationFirewallConfiguration`, `gatewayIPConfigurations`. Zertifikatsdaten werden nicht übernommen. |
| Q-FD | resources | `microsoft.cdn/profiles`, `microsoft.cdn/profiles/afdendpoints`, `microsoft.network/frontdoors` | Front Door Standard/Premium: nur Profile + Endpoints in ARG → Origin Groups, Origins, Routes, Security Policies per ARM (E-FD-01). Front Door (classic) vollständig inline. |
| Q-TM | resources | `trafficmanagerprofiles` | Endpunkte inline |
| Q-BAS | resources | `bastionhosts` | Subnet, Public IP |

## 7. Hybrid-Konnektivität & Virtual WAN

| ID | Tabelle | Typen | Hinweise |
| --- | --- | --- | --- |
| Q-HYB-GW | resources | `virtualnetworkgateways`, `localnetworkgateways`, `connections` | ✔ Typen live; ○ `gatewayType`, `vpnType`, `sku`, `activeActive`, `enableBgp`, `bgpSettings`, `ipConfigurations`; LNG `localNetworkAddressSpace`, `gatewayIpAddress`, `bgpSettings`; Connections `connectionType`, `virtualNetworkGateway1/2`, `localNetworkGateway2`, `peer`, `enableBgp`, `connectionStatus` |
| Q-HYB-ER | resources | `expressroutecircuits`, `expressroutegateways`, `expressrouteports`, `expressroutecrossconnections`, `routefilters` | Circuit-`peerings[]` inkl. `ipv6PeeringConfig` laut API-Modell inline erwartet. Fehlen sie trotz `circuitProvisioningState=Enabled` → ARM E-ER-01. |
| Q-VWAN | resources | `virtualwans`, `virtualhubs`, `virtualhubs/bgpconnections`, `virtualhubs/ipconfigurations`, `vpngateways`, `vpnsites`, `p2svpngateways`, `vpnserverconfigurations`, `virtualrouters`, `securitypartnerproviders` | `virtualhubs` ohne `virtualWan`, aber mit `virtualRouterIps` = **Azure Route Server**. `bgpconnections` = Route-Server- bzw. Hub-BGP-Peers (in ARG, kein ARM nötig). **Nicht** in ARG: `hubVirtualNetworkConnections`, `routingIntent`, `hubRouteTables` → ARM E-VWAN-01…03. |
| Q-NVA | resources | `networkvirtualappliances` | Managed NVAs (vWAN) |

## 8. Private Connectivity & DNS

| ID | Tabelle | Typen | Hinweise |
| --- | --- | --- | --- |
| Q-PE | resources | `privateendpoints`, `privatelinkservices` | ○ `subnet`, `networkInterfaces`, `privateLinkServiceConnections[]` / `manualPrivateLinkServiceConnections[]` (Ziel-ID, `groupIds`, Status), `customDnsConfigs`, `ipConfigurations` |
| Q-DNS-ZONES | resources | `privatednszones`, `privatednszones/virtualnetworklinks`, `dnszones`, `dnsresolvers`, `dnsresolvers/inboundendpoints`, `dnsresolvers/outboundendpoints`, `dnsforwardingrulesets`, `dnsresolverpolicies`, `dnsresolverpolicies/virtualnetworklinks`, `dnssecuritypolicies` | ✔ Zonen, VNet-Links, Resolver, Outbound Endpoints live gesehen |
| Q-DNS-REC | **dnsresources** | `privatednszones/{a,aaaa,cname,ptr,srv,txt,mx}`, `dnsforwardingrulesets/forwardingrules`, `dnsforwardingrulesets/virtualnetworklinks` | ✔ live (A, CNAME, SOA, Forwarding Rules, Ruleset-Links); AAAA laut Tabellenreferenz enthalten. Öffentliche `dnszones/*` werden bewusst **nicht** geladen (Volumen, kein Netzwerkpfadbezug), außer bei `--include-public-dns`. |

Q-DNS-REC-Projektion:
```kusto
dnsresources
| where type in~ ('microsoft.network/privatednszones/a', 'microsoft.network/privatednszones/aaaa',
                  'microsoft.network/privatednszones/cname', 'microsoft.network/privatednszones/ptr',
                  'microsoft.network/privatednszones/srv',
                  'microsoft.network/dnsforwardingrulesets/forwardingrules',
                  'microsoft.network/dnsforwardingrulesets/virtualnetworklinks')
| project id, name, type, tenantId, subscriptionId, resourceGroup, properties
| order by id asc
```

## 9. Compute (nur netzwerkrelevante Felder), Monitoring, Rest

### Q-CMP-VM
```kusto
resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id, name, type, tenantId, subscriptionId, resourceGroup, location, zones, tags,
          vmSize = tostring(properties.hardwareProfile.vmSize),
          nics = properties.networkProfile.networkInterfaces,
          imageReference = properties.storageProfile.imageReference,
          plan,
          powerState = tostring(properties.extended.instanceView.powerState.code)
| order by id asc
```
`imageReference.publisher` und `plan` fließen in die NVA-Heuristik ein (bekannte Firewall-Publisher). `osProfile` wird bewusst nicht projiziert.

### Q-CMP-VMSS
`microsoft.compute/virtualmachinescalesets` → `sku`, `orchestrationMode`, `virtualMachineProfile.networkProfile` (NIC-Templates, `enableIPForwarding`).

### Q-MON
`networkwatchers`, `networkwatchers/flowlogs` (Ziel-NSG/VNet, `enabled`, Retention, Traffic Analytics), `networkwatchers/connectionmonitors`. Diagnostic Settings sind **nicht** in ARG → ARM E-MON-01.

### Q-NET-ALL (Vollständigkeit / `unclassifiedNetworkResources[]`)
```kusto
resources
| where type startswith 'microsoft.network/'
| where type !in~ (<alle oben explizit abgefragten Typen>)
| project $base
| order by id asc
```
Dazu dieselbe Abfrage gegen `networkresources` für dort unbekannte Typen. Jeder Treffer landet unverändert, aber auf `$base` reduziert, in `unclassifiedNetworkResources[]`; der Graph erhält einen Knoten vom Typ `unclassified` mit `contains`-Kante zur Subscription/Resource Group und, falls `properties` Subnet- oder VNet-IDs referenzieren, `attached`-Kanten.

---

## 10. Verifikationsabfragen (Entwicklung/Diagnose)

Die Datei `scripts/verify-arg-coverage.ts` führt ausschließlich aggregierende Abfragen aus und gibt **keine Ressourcendaten** aus:

```kusto
resources | where type startswith 'microsoft.network/' | summarize n = count() by type
```
```kusto
resources | where type =~ '<typ>' | take 20 | mv-expand k = bag_keys(properties) | summarize n = count() by tostring(k)
```
Ergebnis: je Typ die tatsächlich vorhandenen Property-Keys → Abgleich mit den Normalizern (fehlende erwartete Keys → Warnung im Entwicklungsreport).

---

## 11. ARM-Enrichment (nur wo ARG nachweislich nicht reicht)

| ID | Lücke | SDK-Operation (GET) | Auslöser |
| --- | --- | --- | --- |
| E-FW-01 | RCG fehlt in `networkresources` | `FirewallPolicyRuleCollectionGroups.list(rg, policy)` | referenzierte RCG-ID ohne Treffer |
| E-ER-01 | Circuit-Peerings fehlen | `ExpressRouteCircuitPeerings.list(rg, circuit)` | `peerings` leer bei provisioniertem Circuit |
| E-VWAN-01 | Hub-VNet-Connections | `HubVirtualNetworkConnections.list(rg, hub)` | jeder `virtualHub` mit `virtualWan` |
| E-VWAN-02 | Routing Intent | `RoutingIntentOperations.list(rg, hub)` | jeder vWAN-Hub |
| E-VWAN-03 | Hub Route Tables | `HubRouteTables.list(rg, hub)` | jeder vWAN-Hub |
| E-FD-01 | AFD Origin Groups / Origins / Routes / Security Policies / Custom Domains | `@azure/arm-cdn`: `afdOriginGroups.listByProfile`, `afdOrigins.listByOriginGroup`, `routes.listByEndpoint`, `securityPolicies.listByProfile` | jedes `microsoft.cdn/profiles` mit SKU `*_AzureFrontDoor` |
| E-MON-01 | Diagnostic Settings | `GET {id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview` | Azure Firewall, NAT Gateway (StandardV2 Flow Logs), Application Gateway, VPN/ER-Gateways, Front Door |
| E-RT-01 (optional, aus) | Effective Routes | `POST …/networkInterfaces/{nic}/effectiveRouteTable` (Allowlist) | `--effective-routes`, Custom Role |
| E-NSG-01 (optional, aus) | Effective NSG | `POST …/effectiveNetworkSecurityGroups` (Allowlist) | wie oben |

**Entfallen gegenüber der ersten Planung** (jetzt ARG-abgedeckt): Management Groups (Q-ORG-02), VMSS-NICs (Q-NET-VMSSNIC), Route-Server-BGP-Connections (Q-VWAN), Private-DNS-Record-Sets (Q-DNS-REC), DNS-Forwarding-Rules und Ruleset-Links (Q-DNS-REC), Firewall-RCGs (Q-SEC-FWRCG, nur noch Fallback).

## 12. Traceability Lastenheft → Query

| Lastenheft § | Queries / Enrichment |
| --- | --- |
| 10 Organisation | Q-ORG-01, Q-ORG-02 |
| 11 VNets, 12 Subnets, 13 Peerings | Q-NET-VNET (+ Q-SEC-AVNM für AVNM-Konnektivität) |
| 14 Route Tables | Q-NET-RT (+ Q-SEC-AVNM Routing Rules) |
| 15 Azure Firewall | Q-SEC-FW, E-MON-01 |
| 16 Firewall Policy | Q-SEC-FWP, Q-SEC-FWRCG, E-FW-01 |
| 17 NAT Gateway | Q-NET-NAT, Q-NET-PIP, Q-NET-PIPP |
| 18 NSG | Q-NET-NSG, Q-SEC-AVNM |
| 19 NICs | Q-NET-NIC, Q-NET-VMSSNIC, Q-CMP-VM |
| 20/21 Public IP / Prefix | Q-NET-PIP, Q-NET-PIPP |
| 22 Load Balancer | Q-LB |
| 23 Application Gateway | Q-AGW, Q-SEC-WAF |
| 24 Front Door | Q-FD, E-FD-01 |
| 25 VPN Gateway | Q-HYB-GW |
| 26 ExpressRoute | Q-HYB-ER, E-ER-01 |
| 27 Virtual WAN | Q-VWAN, E-VWAN-01…03 |
| 28 Private Endpoints | Q-PE |
| 29 Private DNS | Q-DNS-ZONES, Q-DNS-REC |
| 30 NVAs / Route Server | Q-NVA, Q-VWAN, Q-CMP-VM, Q-NET-NIC |
| 31 Weitere | Q-NET-ALL |
| 48 Monitoring-Gaps | Q-MON, E-MON-01 |
