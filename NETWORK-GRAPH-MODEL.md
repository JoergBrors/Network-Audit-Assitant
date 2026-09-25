# NETWORK-GRAPH-MODEL — Normalisiertes Modell und Beziehungsgraph

Stand 2026-09-25 · Implementierung: `src/models/network.ts`, `src/models/graph.ts`, `src/normalization/normalize.ts`, `src/graph/buildGraph.ts`, `src/topology/classify.ts`, `src/graph/view.ts`

Dieses Dokument beschreibt das **implementierte** Modell. Das Zielmodell mit Evidence, Confidence und Findings steht in [ARCHITECTURE.md § 9](ARCHITECTURE.md).

## 1. Verarbeitung

```text
RawInventory (ARG-Zeilen je Query)
  → normalizeInventory()   NormalizedInventory: typisierte Listen, lowercase-IDs, keine Rohdaten/Secrets
  → classifyTopology()     vnet.topology (Hub/Spoke/…), vm.nva (NVA-Heuristik)
  → buildGraph()           NetworkGraph: Knoten (Hierarchie, LOD, Adressierung) + Beziehungen
= NetworkModel { inventory, graph, discovery }     (src/pipeline/analyze.ts, isomorph, ~40 ms für 3.600 Knoten)
```

## 2. Normalisiertes Inventar

- **IDs**: ARM-Resource-IDs in Kleinschreibung. Synthetische IDs: `tenant:<tenantId>`, `/subscriptions/<id>/locations/<region>` (Region), `internet:ipv4` / `internet:ipv6`, `external` (Sammelknoten).
- **Sammlungen** (gleichzeitig Exportsektionen): `tenants`, `managementGroups`, `subscriptions`, `vnets`, `subnets`, `peerings`, `routeTables`, `routes`, `nsgs`, `networkInterfaces`, `publicIps`, `publicIpPrefixes`, `natGateways`, `firewalls`, `firewallPolicies`, `ruleCollectionGroups`, `ipGroups`, `loadBalancers`, `applicationGateways`, `vpnGateways` (inkl. ExpressRoute-Gateways), `localNetworkGateways`, `connections`, `privateEndpoints`, `privateDnsZones` (inkl. VNet-Links und Records), `dnsResolvers` (Resolver, Endpoints, Rulesets), `virtualMachines`, `scaleSets`, `otherNetworkResources` (generisch modelliert: Bastion, ExpressRoute, vWAN, WAF, Front Door, Flow Logs, …), `unclassifiedNetworkResources` (alle übrigen `Microsoft.Network`-Typen).
- **Adressierung**: `FamilySplit { ipv4[], ipv6[] }` plus `IpClassification` (`ipv4-only | ipv6-only | dual-stack | no-ip | unknown`).
- **Zusammenführungen**:
  - `addressPrefix` und `addressPrefixes` (Subnets) sowie Einzel-/Listenfelder von NSG-Regeln.
  - Subnet → `connectedResourceIds`: Eigentümer aller IP-Konfigurationen im Subnet. VMSS-Instanz-NICs werden zur Scale Set zusammengefasst (AKS mit Azure CNI hat ~30 IP-Konfigurationen pro Knoten).
  - Private-Endpoint-NICs liefern die IP-Adressen des Private Endpoints.
  - Route → `nextHopResourceId`: Auflösung der Next-Hop-IP auf Firewall, LB-Frontend, VM/Scale Set oder NIC.
  - NAT Gateway → `ipv4EgressConfigured`/`ipv6EgressConfigured`/`dualStackEgressConfigured` aus den Familien der Public IPs/Präfixe (SKU-Fähigkeit wird im Assessment bewertet: IPv6 nur StandardV2).
- **Nie übernommen**: Felder, deren Name auf Geheimnisse hindeutet (`sharedKey`, `secret`, `password`, `certificate`, `connectionString`, `sas`, `token`, …), sowie `provisioningState`, `resourceGuid`, `etag`.

## 3. Knoten

| Typ | LOD | Eltern (`parentId`) | Adressierung |
| --- | --- | --- | --- |
| `tenant` | 1 | – | – |
| `subscription` | 1 | Tenant | – |
| `region` | 1 | Subscription | – |
| `vnet` | **1** bei Hub/Spoke, sonst 2 | Region | Address Spaces |
| `subnet` | 3 | VNet | Präfixe |
| `azureFirewall`, `vpnGateway`, `expressRouteGateway`, `applicationGateway`, `bastion`, `routeServer` | 3 | Subnet der IP-Konfiguration (sonst Region) | private IPs |
| `loadBalancer` | 3 | Subnet des Frontends (sonst Region) | Frontend-IPs |
| `natGateway`, `routeTable`, `firewallPolicy`, `localNetworkGateway`, `gatewayConnection`, `virtualHub`, `virtualWan`, `expressRouteCircuit`, `nva`, `dnsResolver` | 3 | Region (Resolver: VNet; Endpoints: Subnet) | teils |
| `vm` | 4 | Subnet der primären NIC | alle NIC-IPs |
| `vmss` | 4 | erstes Subnet | Anzahl IPs je Familie |
| `nic` | 4 | VM (sonst Subnet) | private IPs |
| `privateEndpoint` | 4 | Subnet | private IPs |
| `nsg`, `publicIp`, `publicIpPrefix`, `privateDnsZone`, `dnsForwardingRuleset`, `privateLinkService`, `wafPolicy`, `other`, `unclassified` | 4 | Region | Public IP/Präfix |
| `externalResource` | 2 (VNets) / 4 | Sammelknoten `external` | – |
| `internet` | 2 | – | – |
| `route`, `ruleCollectionGroup`, `ipGroup`, `networkWatcher`, `flowLog` | 5 | Route Table / Policy / Region | Präfix (Route) |

Weitere Knotenfelder: `name`, `tenantId`, `subscriptionId`, `subscriptionName`, `resourceGroup`, `region`, `properties` (kurze Kennwerte; Details stehen im Inventar), `topology` (VNets), `nva` (VMs).

**Externe Knoten:** Ziele von Beziehungen außerhalb des lesbaren Scopes (anderer Tenant, fehlende Rechte, gelöschte Ressourcen, PaaS-Ziele von Private Endpoints) werden als `externalResource` unter `external` angelegt, damit keine Beziehung verloren geht.

## 4. Beziehungen

Kanten-ID: `<typ>:<quelle>-><ziel>[#qualifier]` (deterministisch).

| Typ | Von → Nach | Quelle | Familie |
| --- | --- | --- | --- |
| `contains` | Eltern → Kind | `parentId` | – |
| `peering` | VNet → Remote-VNet (je Seite eine Kante) | `virtualNetworkPeerings`; Eigenschaften: Status, Sync, Flags, Remote-Präfixe je Familie | – |
| `attached` | Subnet → NSG/Route Table; NIC → NSG; Ressource → Public IP/Präfix; AppGW → WAF-Policy; VNet → DDoS-Plan | Referenzen | – |
| `natThrough` | Subnet → NAT Gateway → Public IP/Präfix | NAT Gateway | – |
| `route` | Route → Next-Hop-Ressource bzw. `internet:<familie>` | UDRs | ipv4 / ipv6 |
| `securedBy` | Subnet → Firewall/NVA/LB | Default-Route (`0.0.0.0/0` bzw. `::/0`) der Route Table zeigt auf Firewall/NVA/LB | ipv4 / ipv6 |
| `privateEndpoint` | Private Endpoint → Ziel (Group-IDs, Status) | Private-Link-Verbindungen | – |
| `gatewayConnection` | Gateway → Connection → LNG / Remote-Gateway / ER-Circuit | `connections` | – |
| `dnsLink` | Private-DNS-Zone/Ruleset → VNet | VNet-Links | – |
| `backendOf` | NIC/VM/Scale Set → Load Balancer/Application Gateway | Backend-Pools | – |
| `policyOf` | Firewall Policy → Firewall; Parent-Policy → Child-Policy | Policy-Referenzen | – |
| `monitoredBy` | Ressource → Flow Log | Flow-Log-Ziele | – |
| `connectedTo` | generische Referenzen (z. B. Resolver-Endpoint → Resolver) | übrige Resource-ID-Referenzen | – |

## 5. Topologie-Heuristik (erklärbar)

Jeder Beitrag wird als Klartext in `reasons[]` festgehalten; `confidence` ist die gedeckelte Summe (0–1).

**Hub** (ab 0,5): ≥ 3 Peerings +0,2 (≥ 10: +0,3) · Azure Firewall +0,3 · potenzielle NVA +0,25 · Route Server +0,2 · VPN/ER-Gateway +0,2 · Gateway Transit +0,15 · Default-Routen anderer VNets zeigen hierher +0,25.

**Spoke** (ab 0,4): `useRemoteGateways` +0,35 · Peering mit Hub +0,3 · Default-Route auf Appliance im Hub +0,35 (in anderes VNet: +0,2) · ≤ 2 Peerings +0,1.

**Shared Services** (ab 0,35 und ≥ Spoke-Wert; Konfidenz +0,2): DNS Private Resolver +0,35 · Bastion +0,15 · ≥ 10 Private Endpoints +0,2 · ≥ 3 Peerings ohne Hub-Signale +0,15.

**Standalone**: keine Peerings (0,9). Sonst **unknown** (0,3) mit allen gefundenen Signalen.

**NVA-Heuristik (VMs)** (potenziell ab 0,5): IP Forwarding +0,35 · UDR-Next-Hop +0,4 · mehrere NICs in verschiedenen Subnets +0,15 · Marketplace-Image eines Netzwerkherstellers +0,2.

## 6. Sichtbarkeit in der UI (`computeVisibleGraph`)

- **Level of Detail**: sichtbar sind Knoten mit `lod ≤ Stufe` sowie Kinder aufgeklappter Knoten. Knoten mit sichtbaren Kindern werden zu Containern.
- **Kanten-Lifting**: Beziehungen zu verborgenen Knoten werden zum nächsten sichtbaren Vorfahren hochgezogen und zusammengefasst (`count`). Kanten zwischen Vorfahr und Nachfahr entfallen.
- **Fokus**: Teilbaum plus direkt verbundene Knoten, höchstens auf Stufe 4 (Routen werden zur Route Table zusammengefasst, Organisationsknoten nie als Nachbarn).
- **Filter** (IP-Modus, „Nur Änderungen“): `emphasis = match | context | normal`. `match` = Knoten erfüllt alle aktiven Filter (eigene Adressen der Familie bzw. Dual Stack; geändert oder Änderung darunter). `context` = direkt verbunden mit einem Treffer oder Container eines Treffers. Alles andere wird ausgeblendet; Kanten ohne passendes Ende werden als Hintergrund markiert.
- **Grenze**: mehr als 1.500 sichtbare Knoten → Hinweis statt Graph.

## 7. Exportform des Graphen

Im JSON-Export (`graph`) ist der Graph kompakt:

- keine `contains`-Kanten (Hierarchie über `nodes[].parentId`)
- keine `route`-Knoten (einzelne Routen stehen in `routes`)
- Routen-Kanten starten an der Route Table (`properties.route` = Routenname)

Beim Import wird der vollständige Graph deterministisch aus dem Inventar neu aufgebaut. Realer Tenant: ~9 MB Export bei 3.662 Knoten.
