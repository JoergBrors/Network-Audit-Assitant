# ARCHITECTURE — Azure Network Audit Assistant

Status: Entwurf Phase 2 · Stand 2026-09-25 · Schema-Version (geplant) `1.0.0`

Dieses Dokument beschreibt die Zielarchitektur eines vollständig **read-only** arbeitenden Tools, das Azure-Netzwerklandschaften tenant- und subscriptionübergreifend inventarisiert, zu einem normalisierten Netzwerkgraphen rekonstruiert, IPv4/IPv6 gleichwertig analysiert (Schwerpunkt Dual-Stack-Gap-Analyse), Architektur-Findings mit Evidence erzeugt und als Snapshot/JSON/Draw.io exportiert.

---

## 1. Ausgangslage (Repository-Analyse, Phase 1)

| Befund | Konsequenz |
| --- | --- |
| Repository enthält nur `LICENSE` (MIT, 2026) und einen Initial-Commit. | Greenfield. Keine Bestandsdateien, die überschrieben werden könnten. |
| Lokale Toolchain: Node `26.0.0`, npm `11.12.1`, Azure CLI `2.84.0` mit `resource-graph`-Extension, angemeldet. | Node ≥ 22 LTS als Mindestversion; `AzureCliCredential` ist für die Entwicklung sofort nutzbar. |
| `typescript-eslint@8.70` unterstützt TypeScript `>=4.8.4 <6.1.0`; TypeScript 7 (nativer Port) ist nicht kompatibel. | **TypeScript 6.0.x** wird gepinnt. Wechsel auf TS 7 erst, wenn typescript-eslint es offiziell unterstützt. |

### 1.1 Verifizierte SDK-/API-Versionen (npm-Registry, 2026-09-25)

| Paket | Version | ARM-API-Version im SDK | Verwendung |
| --- | --- | --- | --- |
| `@azure/identity` | 4.13.3 | – | `DefaultAzureCredential`, `AzureCliCredential`, `ManagedIdentityCredential`, `WorkloadIdentityCredential`, `VisualStudioCodeCredential` |
| `@azure/arm-resourcegraph` | 5.0.0 | `2024-04-01` | Primäre Discovery (`client.resources(QueryRequest)`) |
| `@azure/arm-network` | 39.0.0 | `2026-01-01` | Gezielte Enrichment-GETs |
| `@azure/arm-resources-subscriptions` | 3.0.0 | `2022-12-01` | Tenants/Subscriptions (`tenants.list`, `subscriptions.list`) |
| `@azure/msal-browser` | 5.23.0 | – | Anmeldung der Web-UI (Auth Code + PKCE) |
| `@azure/arm-privatedns` | 4.0.0 | `2024-06-01` | Fallback für Record Sets |
| `@azure/arm-dnsresolver` | 1.2.0 | `2025-05-01` | Fallback für Resolver-Kinder |
| `@azure/arm-cdn` | 10.0.0 | `2025-12-01` | Front Door Standard/Premium (Origins, Routes) |
| `@xyflow/react` | 12.12.0 | – | Topologie |
| `elkjs` | 0.12.0 | – | Layout |
| `zod` | 4.6.5 | – | Schema/Validierung |
| `vitest` | 5.0.1 | – | Tests |

`QueryRequestOptions` in `@azure/arm-resourcegraph@5` bietet: `skipToken`, `top`, `skip`, `resultFormat`, `allowPartialScopes`, `authorizationScopeFilter`. `QueryResponse` liefert `totalRecords`, `count`, `resultTruncated`, `skipToken`, `data`.

`@azure/arm-network@39` (API `2026-01-01`) enthält u. a.: `NatGatewaySkuName = Standard | StandardV2`, `RouteNextHopType = VirtualNetworkGateway | VnetLocal | Internet | VirtualAppliance | VirtualApplianceEcmp | None`, `Subnet.defaultOutboundAccess`, `Subnet.addressPrefixes`, `Subnet.sharingScope`, `Subnet.serviceGateway`, `VirtualNetwork.encryption`, `VirtualNetwork.flowTimeoutInMinutes`, `VirtualNetworkPeering.peerCompleteVnets/localSubnetNames/remoteSubnetNames` (Subnet-Peering), `NatGateway.sourceVirtualNetwork`.

### 1.2 Live-Verifikation gegen Azure Resource Graph (read-only, aggregierte Abfragen)

Gegen den angemeldeten Tenant wurden ausschließlich aggregierende ARG-Abfragen (`summarize count() by type`, `bag_keys(properties)`) ausgeführt. Ergebnisse, die das Design bestimmen:

| Frage | Ergebnis | Designentscheidung |
| --- | --- | --- |
| Sind Subnets/Peerings inline am VNet? | Ja: `properties.subnets[]`, `properties.virtualNetworkPeerings[]` inkl. `remoteAddressSpace`, `remoteVirtualNetworkAddressSpace`, `peerCompleteVnets`, `peeringSyncLevel`, `remoteGateways`, `routeServiceVips`. Subnets enthalten `ipConfigurations[]` (IDs). | Keine separaten Peering-/Subnet-Calls nötig. |
| Firewall-Policy Rule Collection Groups? | **Nicht** in `resources`, aber in Tabelle **`networkresources`** (`microsoft.network/firewallpolicies/rulecollectiongroups`) inkl. `ruleCollections[].rules[]` mit `sourceAddresses`, `destinationAddresses`, `sourceIpGroups`, `destinationIpGroups`, `destinationPorts`, `destinationFqdns`, `ipProtocols`, `ruleType`, **`ipv6Rule`**. | ARG-first über `networkresources`; ARM nur als Fallback (Truncation/Fehler). |
| Classic-Firewall-Regeln? | Inline in `azurefirewalls.properties.{application,network,nat}RuleCollections`. | Kein Enrichment. |
| Private-DNS-Records / Resolver-Regeln? | Tabelle **`dnsresources`**: `privatednszones/a`, `.../cname`, `.../soa`, `dnsforwardingrulesets/forwardingrules`, `dnsforwardingrulesets/virtualnetworklinks`. | ARG-first über `dnsresources`; `@azure/arm-privatedns` nur Fallback. |
| Private-DNS-VNet-Links, Resolver-Endpoints? | In `resources`: `privatednszones/virtualnetworklinks`, `dnsresolvers/outboundendpoints`. | ARG. |
| NAT Gateway? | `sku.name`, `properties.subnets`, `publicIpAddresses`, `idleTimeoutInMinutes`, (optional) `publicIpPrefixes`. | ARG. |
| Management Groups? | In `resourcecontainers` nur mit Management-Group-Scope (Root-MG = Tenant-ID) sichtbar, dann vollständig (live verifiziert). Subscriptions tragen zusätzlich `managementGroupAncestorsChain`. | ARG mit MG-Scope (Q-ORG-02), kein ARM nötig. |
| Properties ohne Wert? | ARG lässt nicht gesetzte Properties weg (z. B. `addressPrefixes` fehlt, wenn nur `addressPrefix` gesetzt). | Normalisierung muss beide Formen (`addressPrefix` und `addressPrefixes`) zusammenführen. |

Phase 3 hat die offenen Punkte gegen die offizielle ARG-Tabellenreferenz geklärt (Details: [RESOURCE-GRAPH-QUERIES.md](RESOURCE-GRAPH-QUERIES.md)):
- **In ARG:** Management Groups (`resourcecontainers`, nur mit MG-Scope, live verifiziert), VMSS-NICs (`computeresources`, live verifiziert), Route-Server-/Hub-BGP-Connections (`virtualhubs/bgpconnections`), Private-DNS-AAAA-Records (`dnsresources`), **Azure Virtual Network Manager** (effektive Security Admin Rules, Connectivity- und Routing-Konfigurationen in `networkresources`).
- **Nicht in ARG → ARM:** vWAN `hubVirtualNetworkConnections`, `routingIntent`, `hubRouteTables`; Front Door Standard/Premium Origin Groups/Origins/Routes/Security Policies; Diagnostic Settings.

### 1.3 Belegte Azure-Verhaltensregeln (Microsoft Learn), die die Analyse steuern

- **NAT Gateway Standard** unterstützt **keine** IPv6-Public-IPs; **StandardV2** unterstützt bis zu 16 IPv4 + 16 IPv6 Public IPs bzw. IPv6-Prefix (/124), zusätzlich NAT64 (`64:ff9b::/96`). StandardV2 benötigt StandardV2-Public-IPs. NAT Gateway wird in Secured Virtual Hubs (vWAN) nicht unterstützt und nicht am GatewaySubnet.
- **Outbound-Priorität**: UDR mit Next Hop VirtualAppliance/VirtualNetworkGateway > NAT Gateway > Instance-Level Public IP > Load-Balancer-Outbound-Rules > Default Outbound Access.
- **Default Outbound Access**: Für VNets, die mit API-Versionen nach 2026-03-31 erstellt wurden, ist `defaultOutboundAccess=false` Standard; bestehende VNets unverändert. → Pro Subnet explizit auswerten, fehlender Wert = „vom Erstellungszeitpunkt abhängig" → Konfidenz `LIKELY`.

---

## 2. Leitprinzipien

1. **Read-only by construction** – nicht nur per Konvention, sondern technisch erzwungen (§ 4).
2. **Evidence first** – jede Klassifikation, jeder Pfad-Hop, jedes Finding trägt `evidence[]` und `confidence`. Fehlende Daten erzeugen `UNKNOWN`, niemals eine erfundene Aussage.
3. **Ein Modell, viele Sichten** – UI, JSON-Export, Draw.io, SVG, Diff: alle aus demselben normalisierten `NetworkGraph`/`NetworkInventory`.
4. **IPv4 = IPv6** – jede Adress-, Routing-, Security- und Egress-Auswertung läuft pro Adressfamilie mit identischem Code; Dual-Stack ist ein Vergleich zweier gleichwertiger Ergebnisse.
5. **Isomorpher Kern** – Normalisierung, Analyse, Assessment, Snapshot, Diff und Export haben keine Azure- oder Node-Abhängigkeit und laufen im Browser (Snapshot-Import offline) wie in der CLI.
6. **Fehlerisolation** – ein unlesbarer Scope/Ressource erzeugt `warnings[]` und senkt die Konfidenz, bricht aber nie die Discovery ab.

---

## 3. Systemübersicht

```
            CLI (Node)                                        Web-UI (Browser, statische SPA)
┌─────────────────────────────────┐              ┌──────────────────────────────────────────────────┐
│ auth/node: DefaultAzureCredential│              │ auth/browser: MSAL (Auth Code + PKCE)            │
│  (CLI, VS Code, MI, Workload Id) │              │  → MsalTokenCredential (TokenCredential)         │
└───────────────┬─────────────────┘              └───────────────────────┬──────────────────────────┘
                │ TokenCredential                                          │ TokenCredential
                ▼                                                          ▼
┌───────────────────────────── azure/* + discovery (isomorph, Azure SDK) ─────────────────────────────┐
│ readOnlyGuardPolicy → subscriptions → resourceGraph (ARG, Paging, Batching, Retry) → arm (Enrichment)│
│ → RawInventory + DiscoveryQuality + warnings                     Cache: Datei (CLI) / Memory (UI)   │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                ▼
┌──────────────────────────────────── core (isomorph, ohne Azure-SDK) ────────────────────────────────┐
│ normalization → addressing → graph → topology (Hub/Spoke) → routing → security → dualstack          │
│ → assessment → snapshots → drift → export                                                            │
└───────────────┬───────────────────────────────────────────────────────────────┬──────────────────────┘
                ▼                                                               ▼
   cli: discover/assess/export/snapshot/diff          UI: Dashboard · Topologie (React Flow + ELK-Worker)
                                                      · Tree View · Detail Panel · Suche · Filter
                                                      · Path Trace · IPv4/IPv6-Compare · Findings · Drift
                                                      · Snapshot-Import (offline)
```

Die Web-UI ruft `https://management.azure.com` (ARM und ARG) **direkt aus dem Browser** auf. Verifiziert am 2026-09-25: ARM beantwortet CORS-Preflights für `POST /providers/Microsoft.ResourceGraph/resources` und `GET /subscriptions` mit `access-control-allow-origin: *` und `access-control-allow-headers: authorization,content-type`. Ein Backend ist daher nicht erforderlich. Tokens verlassen den Browser nur in Richtung `login.microsoftonline.com` und `management.azure.com`.

### 3.1 Betriebsmodi

| Modus | Auth | Datenquelle | Zweck |
| --- | --- | --- | --- |
| **Web-UI** (Standard für interaktive Nutzung) | **MSAL Browser**, Authorization Code Flow mit PKCE, Entra-App-Registrierung als SPA (nur Client-ID, **kein** Secret), siehe [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md) | Azure live, direkt aus dem Browser | Interaktive Analyse, statisch hostbar (lokal `vite`, oder Static Web Hosting) |
| **CLI** | `DefaultAzureCredential` (Env, Workload Identity, Managed Identity, VS Code, Azure CLI) | Azure live | Pipelines, geplante Snapshots, Exporte |
| **Offline-UI** | keine Anmeldung | importierter Snapshot | Review ohne Azure-Zugriff, Snapshot-Vergleich |

Beide Auth-Wege liefern ein `TokenCredential` (`@azure/core-auth`). Discovery-Code ist davon unabhängig und läuft unverändert in Node und im Browser.

---

## 4. Read-only-Garantie

Alle Azure-SDK-Clients werden ausschließlich über eine Factory `createReadOnlyClient()` erzeugt, die eine **HTTP-Pipeline-Policy `readOnlyGuardPolicy`** (Position `perCall`) injiziert:

- `GET` (und `HEAD`) → erlaubt.
- `POST` → nur gegen eine explizite Allowlist lesender Operationen:
  - `POST /providers/Microsoft.ResourceGraph/resources` (ARG-Query),
  - optional, standardmäßig **deaktiviert**: `.../networkInterfaces/{nic}/effectiveRouteTable` und `.../effectiveNetworkSecurityGroups` (liefern Laufzeitdaten, benötigen aber Actions außerhalb von *Reader* — § 5).
- `PUT`, `PATCH`, `DELETE`, sonstige `POST` → **harte Exception** vor dem Versand (`ReadOnlyViolationError`), inklusive Logeintrag.

Zusätzlich: ESLint-Regel (`no-restricted-syntax`) gegen Aufrufe von `begin*`, `createOrUpdate*`, `update*`, `delete*` auf SDK-Clients; ein Unit-Test prüft die Policy für alle Methoden. Es gibt keine Deploy-, Fix- oder Remediation-Funktionen; Recommendations sind reiner Text.

---

## 5. Authentifizierung & RBAC

### 5.1 Authentifizierung — Web-UI (MSAL)

- Bibliothek: `@azure/msal-browser` 5.x (ohne `msal-react`; die App nutzt eine schlanke Session-Abstraktion `src/auth/browser/session.ts`). Flow: **Authorization Code Flow mit PKCE** (MSAL.js unterstützt keinen Implicit Flow).
- Konfiguration ausschließlich über Build-/Laufzeit-Konfiguration, keine fest codierten IDs:
  - `VITE_ENTRA_CLIENT_ID` (Pflicht): Application (client) ID der SPA-Registrierung.
  - `VITE_ENTRA_AUTHORITY` (optional): Default `https://login.microsoftonline.com/organizations`; für Single-Tenant-Registrierungen `https://login.microsoftonline.com/<tenantId>`.
  - `redirectUri` = `window.location.origin` (muss als SPA-Redirect-URI registriert sein).
- **Scope**: `https://management.azure.com/user_impersonation`. Das ist die einzige delegierte Berechtigung der Ressource *Azure Resource Manager* (AppId `797f4846-ba00-4fd7-ba43-dac1f8f63013`, Scope-ID `41094075-9dad-400e-a0bd-54e686782033`, Typ „User“: ein Benutzer kann ihr selbst zustimmen). Deckt ARM **und** Azure Resource Graph ab.
- Anmeldung: `loginPopup` (Default) bzw. `loginRedirect` (Fallback bei Popup-Blockern). Token-Bezug: immer zuerst `acquireTokenSilent`; bei `InteractionRequiredAuthError` (abgelaufener Refresh Token nach 24 h für SPAs, Conditional Access, MFA) `acquireTokenPopup`.
- **`MsalTokenCredential`** (`src/auth/browser`) implementiert `TokenCredential.getToken(scopes, { tenantId })` und setzt pro Tenant die Authority `https://login.microsoftonline.com/<tenantId>`. So erhält jeder Tenant sein eigenes, korrekt ausgestelltes Token (Home-Tenant, Gast-Tenants).
- **Token-Cache**: `sessionStorage` (Default, gelöscht beim Schließen des Tabs), alternativ `memoryStorage` (dann nur Popup-Flow). Kein `localStorage`. Die App selbst speichert, loggt oder exportiert keine Tokens; sie gibt sie nur über das `Authorization`-Header an `management.azure.com`.
- **Content Security Policy** der SPA: `connect-src 'self' https://login.microsoftonline.com https://management.azure.com`; `frame-src https://login.microsoftonline.com` (silent renew).
- Abmelden: `logoutPopup`, leert den MSAL-Cache und den In-Memory-Discovery-Cache.

### 5.2 Authentifizierung — CLI (DefaultAzureCredential)

- `DefaultAzureCredential` (Reihenfolge laut SDK: Environment → Workload Identity → Managed Identity → VS Code → Azure CLI → PowerShell → Azure Developer CLI). Per `--credential cli|vscode|mi|workload|default` kann eine Quelle erzwungen werden.
- Tenant-gebundene Tokens über `getToken(scopes, { tenantId })` mit `additionallyAllowedTenants: ["*"]`.

### 5.3 Multi-Tenant (beide Wege)

- `SubscriptionClient.tenants.list()` liefert alle Tenants des Benutzers; Discovery läuft pro Tenant mit tenant-gebundenem Token. Scheitert ein Tenant (fehlende Zustimmung, MFA/Conditional Access, Gastbeschränkung) → `warning` `TenantTokenUnavailable`, der Rest läuft weiter.
- Azure-Lighthouse-delegierte Subscriptions erscheinen bereits im Home-Tenant.
- `--tenant <id>` bzw. Tenant-Auswahl in der UI schränkt ein. Keine fest codierten IDs.
- Tokens werden nie geloggt, nie persistiert (außer im MSAL-Session-Cache), nie exportiert. Der Logger hat einen Redaction-Filter für `authorization`, `token`, `secret`, `key`, `password`, `sas`, `sig=`.

### 5.4 Warum Read-only trotz `user_impersonation`

ARM bietet **keinen** reinen Lese-Scope: `user_impersonation` erlaubt dem Token alles, was die Azure-RBAC-Rollen des Benutzers erlauben. Deshalb gilt Read-only auf drei Ebenen:
1. **Technisch in der App**: `readOnlyGuardPolicy` (§ 4) blockiert jeden Nicht-Lese-Request, bevor er gesendet wird, in Browser und CLI.
2. **Azure RBAC**: Empfohlen ist ein Konto bzw. eine Gruppe, die nur `Reader` hat.
3. **Entra ID**: Optional „Assignment required“ an der Enterprise Application, damit nur freigegebene Benutzer das Tool verwenden können, plus Conditional Access.

### 5.5 Minimale Rechte (Azure RBAC)

| Stufe | Rolle | Liefert |
| --- | --- | --- |
| **Pflicht** | `Reader` auf Subscriptions/MGs (ARG respektiert RBAC automatisch) | Vollständige Konfigurations-Discovery inkl. Firewall-Policies, NSG-Regeln, UDRs, Private DNS Records |
| Optional | `Management Group Reader` (bzw. Reader auf MG-Ebene) | MG-Hierarchie |
| Optional | Custom Role mit `Microsoft.Network/networkInterfaces/effectiveRouteTable/action`, `.../effectiveNetworkSecurityGroups/action` | Tatsächlich wirksame (inkl. BGP-gelernter) Routen/NSG-Regeln pro NIC; erhöht Routing-Konfidenz von `LIKELY` auf `CONFIRMED` |
| Optional | `Microsoft.Network/networkWatchers/*/read` (in Reader enthalten) | Flow-Log-/Connection-Monitor-Konfiguration für Monitoring-Gaps |

Kein `Contributor`/`Owner`. Fehlende Rechte → `warnings[]` + `accessStatus: "not-accessible"` am betroffenen Knoten.

---

## 6. Modul- und Komponentenstruktur

Einzelnes npm-Paket (keine Workspaces, reduziert Build-Komplexität); Schichtgrenzen werden per ESLint (`no-restricted-imports`) erzwungen.

```
src/
  auth/
    browser/            MSAL-Konfiguration, MsalTokenCredential (TokenCredential), Login/Logout
    node/               DefaultAzureCredential-Factory, Tenant-Wrapper
  azure/
    http/               readOnlyGuardPolicy, Retry/Backoff, Throttling (x-ms-user-quota-*), Concurrency-Limiter
    subscriptions/      Tenants, Subscriptions, Management Groups
    resourceGraph/      ARG-Client, Query-Katalog (*.kql.ts), Paging, Subscription-Batching, Cache
    arm/                Enrichment-Clients (network, privatedns, dnsresolver, cdn), Enrichment-Plan & Cache
  discovery/            Pipeline-Orchestrierung → RawInventory + DiscoveryQuality + warnings
  models/               Zod-Schemas + abgeleitete Typen (Raw, Normalized, Graph, Findings, Snapshot, Diff)
  normalization/        Raw → NormalizedInventory (pro Ressourcentyp ein Normalizer), unclassified-Fallback
  addressing/           IPv4/IPv6 CIDR-Arithmetik (bigint), Containment, Overlap, IP-Index, Klassifikation
  graph/                NetworkGraph-Builder (Nodes/Edges/Relationships), Indizes
  topology/             Hub/Spoke/Shared-Services/NVA-Heuristiken, Hierarchie (Tenant→Sub→Region→VNet→Subnet)
  routing/              Effective-Route-Synthese, LPM, Path-Tracer, Egress-Resolver
  security/             NSG-Evaluator, Firewall-Regel-Modell, Exposure-Analyse
  dualstack/            Matrix, Gap-Erkennung, Readiness pro Kategorie
  assessment/           Rule-Engine, Regelkatalog, ArchitectureGaps, AssessmentContext
  snapshots/            Snapshot-Builder, kanonische Serialisierung, configurationHash, Import/Validierung
  drift/                Semantic Diff, Drift-Klassifikation, Finding-Lifecycle, Timeline, Baseline
  export/               JSON, Sanitizer, Draw.io, SVG, CSV
  logging/              Strukturiertes Logging (JSON Lines), Redaction
  utils/                Concurrency, stabile Sortierung, IDs
  cli/                  commander-Kommandos
  ui/                   React-App (Vite)
    components/         Topology, TreeView, DetailPanel, Search, Filters, PathTrace, Compare, Dashboard, Drift
    hooks/              useGraph, useSelection, useLayout (Worker), useFilters
    state/              Zustand-Store (Selection, Filter, LOD, Expand-State)
    workers/            elk.worker.ts, search.worker.ts
    theme/              CSS-Tokens (--network-ipv4 …), Light/Dark
tests/
  fixtures/             Synthetische ARG-förmige Rohdaten (keine echten Tenantdaten)
  scenarios/            Szenario-Builder für Akzeptanztests 1–7
```

**Abhängigkeitsregel (erzwungen):** `ui` → `core`-Module; `core` (`models`…`export`) → keine Imports aus `azure`, `auth`, `cli`, `ui`, keine Node-Builtins. `azure`/`discovery` → `models`, `utils`, `logging`, keine Node-Builtins (Cache-Adapter werden injiziert). `auth/browser` nur aus `ui`, `auth/node` nur aus `cli`.

---

## 7. Discovery-Strategie (Azure Resource Graph first)

### 7.1 Ablauf

1. **Tenants** (`tenants.list`) → **Subscriptions** (`subscriptions.list` je Tenant; Status `Enabled`/`Warned`/`PastDue` werden abgefragt, `Disabled` als Warnung).
2. **Management Groups** (optional, ARM).
3. **ARG-Queries** aus einem versionierten Katalog, je Query:
   - Scope: Subscription-Batches (Default 200 IDs/Request, konfigurierbar), je Tenant.
   - Paging: `top: 1000`, `skipToken` bis erschöpft; `resultTruncated === "true"` ohne `skipToken` → Warnung + Query-Split nach Subscription.
   - Deterministische Sortierung (`order by id asc`) für stabiles Paging.
   - Projektion: nur benötigte Felder (reduziert Payload, verhindert Rohdaten-Leaks in Exporte).
4. **Raw Inventory** (`RawInventory`: Map `type → RawResource[]`, plus `queryStats`).
5. **ARM-Enrichment** nur für Lücken (§ 8), mit Cache und Concurrency-Limit.
6. **Discovery Quality** wird parallel mitgeschrieben (§ 15).

### 7.2 Resilienz
- Concurrency: globaler Limiter (Default ARG 4 parallel, ARM 8 parallel).
- Retry: exponentieller Backoff mit Jitter für 429/5xx/`ECONNRESET`; `Retry-After` wird respektiert; ARG-Header `x-ms-user-quota-remaining`/`x-ms-user-quota-resets-after` steuern proaktives Drosseln.
- Fehlerisolation pro (Tenant × Query × Batch). Ein 403 auf einem Batch → Aufsplitten bis zur einzelnen Subscription, um die unlesbare zu identifizieren.
- Cache: austauschbarer Adapter — Datei (`.cache/`, CLI) bzw. In-Memory pro Tab (UI, keine Persistenz im Browser), Key = `hash(query, scope, apiVersion)`, TTL Default 15 min, `--no-cache` schaltet ab. Cache enthält nur Ressourcendaten, keine Tokens.
- ARG ist „near real time"; Änderungen der letzten Minuten können fehlen → im `snapshotMetadata` dokumentiert.

### 7.3 Query-Katalog (Kurzfassung; vollständig in `RESOURCE-GRAPH-QUERIES.md`, Phase 3)

| ID | Tabelle | Typen |
| --- | --- | --- |
| Q-ORG-01 | `resourcecontainers` | `microsoft.resources/subscriptions`, `.../resourcegroups` (Tags, Location) |
| Q-NET-VNET | `resources` | `virtualnetworks` inkl. inline `subnets`, `virtualNetworkPeerings` |
| Q-NET-RT | `resources` | `routetables` (inline `routes`, `subnets`, `disableBgpRoutePropagation`) |
| Q-NET-NSG | `resources` | `networksecuritygroups` (inline `securityRules`, `defaultSecurityRules`, `subnets`, `networkInterfaces`) |
| Q-NET-NIC | `resources` | `networkinterfaces` (ipConfigurations, `enableIPForwarding`, `enableAcceleratedNetworking`, `virtualMachine`, NSG) |
| Q-NET-PIP / Q-NET-PIPP | `resources` | `publicipaddresses`, `publicipprefixes` |
| Q-NET-NAT | `resources` | `natgateways` |
| Q-NET-FW / Q-NET-FWP | `resources` | `azurefirewalls`, `firewallpolicies`, `ipgroups` |
| Q-NET-FWRCG | `networkresources` | `firewallpolicies/rulecollectiongroups` |
| Q-NET-LB / Q-NET-AGW | `resources` | `loadbalancers`, `applicationgateways`, `applicationgatewaywebapplicationfirewallpolicies` |
| Q-NET-GW | `resources` | `virtualnetworkgateways`, `localnetworkgateways`, `connections`, `expressroutecircuits`, `expressroutegateways`, `expressrouteports` |
| Q-NET-VWAN | `resources` | `virtualwans`, `virtualhubs`, `vpngateways`, `vpnsites`, `p2svpngateways` |
| Q-NET-PE | `resources` | `privateendpoints`, `privatelinkservices` |
| Q-DNS-ZONES | `resources` | `privatednszones`, `privatednszones/virtualnetworklinks`, `dnszones`, `dnsresolvers(/inboundendpoints,/outboundendpoints)`, `dnsforwardingrulesets` |
| Q-DNS-REC | `dnsresources` | `privatednszones/{a,aaaa,cname,…}`, `dnsforwardingrulesets/{forwardingrules,virtualnetworklinks}` |
| Q-NET-NVA | `resources` | `networkvirtualappliances`, `virtualhubs` (Route Server = virtualHub ohne `virtualWan`), `bastionhosts` |
| Q-CMP-VM | `resources` | `microsoft.compute/virtualmachines` (Name, NIC-Referenzen, Image-Publisher für NVA-Heuristik), `virtualmachinescalesets` |
| Q-FD | `resources` | `microsoft.cdn/profiles`, `profiles/afdendpoints`, `microsoft.network/frontdoors`, `frontdoorwebapplicationfirewallpolicies` |
| Q-MON | `resources` | `networkwatchers`, `networkwatchers/flowlogs`, `networkwatchers/connectionmonitors` |
| Q-NET-ALL | `resources` + `networkresources` | `type startswith 'microsoft.network/'` minus alle obigen → `unclassifiedNetworkResources[]` |

---

## 8. ARM-Enrichment (nur für Lücken)

Der verbindliche Enrichment-Katalog (IDs `E-*`) steht in [RESOURCE-GRAPH-QUERIES.md § 11](RESOURCE-GRAPH-QUERIES.md). Kurzfassung:

| Datenlücke | ARM-Call (read-only GET) |
| --- | --- |
| vWAN Hub-VNet-Connections, Routing Intent, Hub Route Tables | `HubVirtualNetworkConnections.list`, `RoutingIntentOperations.list`, `HubRouteTables.list` |
| Front Door Std/Premium Kinder | `@azure/arm-cdn` `afdOriginGroups`, `afdOrigins`, `routes`, `securityPolicies` |
| Diagnostic Settings der Kontrollpunkte | `GET {id}/providers/Microsoft.Insights/diagnosticSettings` |
| Fallbacks (nur bei Lücken/Truncation) | Firewall-RCGs, ExpressRoute-Circuit-Peerings |
| Optional, standardmäßig aus | Effective Routes / Effective NSG (POST-Allowlist, Custom Role) |

Enrichment-Cache: Key `resourceId + etag` (sofern vorhanden) + apiVersion. Jeder Call erzeugt einen `EnrichmentResult { resourceId, operation, status: ok|notFound|forbidden|throttled|error }` für die Discovery-Quality.

---

## 9. Normalisiertes Datenmodell

Alle Typen werden als Zod-Schemas in `src/models` definiert; TypeScript-Typen werden per `z.infer` abgeleitet. Keine UI-Komponente sieht Rohdaten.

### 9.1 Basis

```ts
type IpFamily = "ipv4" | "ipv6";
type IpClassification = "ipv4-only" | "ipv6-only" | "dual-stack" | "no-ip" | "unknown";
type Confidence = "CONFIRMED" | "LIKELY" | "POSSIBLE" | "UNKNOWN";
type AccessStatus = "ok" | "partial" | "not-accessible";

interface Evidence {
  kind: "property" | "route" | "rule" | "relationship" | "heuristic" | "missing-data";
  resourceId?: string;
  path?: string;              // z. B. "properties.routes[2].nextHopType"
  value?: unknown;            // bereinigter Wert, niemals Secrets
  description: string;
}

interface Cidr { family: IpFamily; prefix: string; network: string; length: number }

interface Addressing {
  ipv4: string[];             // CIDRs bzw. /32
  ipv6: string[];             // CIDRs bzw. /128
  classification: IpClassification;
}
```

### 9.2 NetworkGraph

```ts
type NodeType =
  | "tenant" | "managementGroup" | "subscription" | "region" | "resourceGroup"
  | "vnet" | "subnet" | "peering" | "routeTable" | "route" | "nsg" | "nsgRule"
  | "nic" | "ipConfiguration" | "vm" | "vmss" | "publicIp" | "publicIpPrefix"
  | "natGateway" | "azureFirewall" | "firewallPolicy" | "ruleCollectionGroup" | "firewallRule" | "ipGroup"
  | "loadBalancer" | "applicationGateway" | "wafPolicy" | "frontDoorProfile" | "frontDoorEndpoint" | "frontDoorOrigin"
  | "vpnGateway" | "expressRouteGateway" | "expressRouteCircuit" | "localNetworkGateway" | "gatewayConnection"
  | "virtualWan" | "virtualHub" | "routeServer" | "nva" | "bastion"
  | "privateEndpoint" | "privateLinkService" | "privateDnsZone" | "dnsRecordSet" | "dnsResolver" | "dnsForwardingRuleset"
  | "internet" | "onPremises" | "unclassified";

type EdgeType =
  | "contains" | "peering" | "route" | "attached" | "securedBy" | "natThrough" | "connectedTo"
  | "privateEndpoint" | "gatewayConnection" | "dnsLink" | "internetEgress"
  | "nextHop" | "associatedPublicIp" | "backendOf" | "policyOf";

interface GraphNode {
  id: string;                  // ARM-Resource-ID, lowercase-normalisiert; synthetische Knoten: "synthetic:internet:ipv6"
  type: NodeType;
  name: string;
  tenantId?: string;
  subscriptionId?: string;
  subscriptionName?: string;
  resourceGroup?: string;
  region?: string;
  parentId?: string;           // Hierarchie für Tree/Cluster
  lod: 1 | 2 | 3 | 4 | 5;      // Level of Detail
  tags?: Record<string, string>;
  properties: Record<string, unknown>;   // typ-spezifisch, per Zod diskriminiert
  addressing: Addressing;
  security?: { nsgIds: string[]; firewallIds: string[]; exposure?: ExposureSummary };
  routing?: { routeTableId?: string; defaultRoute: Record<IpFamily, DefaultRouteSummary | null> };
  topology?: TopologyClassification;     // nur VNets
  nva?: NvaClassification;               // nur VMs/NICs
  accessStatus: AccessStatus;
  findingIds: string[];
}

interface GraphEdge {
  id: string;                  // deterministisch: `${type}:${source}->${target}[:qualifier]`
  source: string;
  target: string;
  type: EdgeType;
  family?: IpFamily | "both";
  properties: Record<string, unknown>;
}

interface NetworkGraph { nodes: GraphNode[]; edges: GraphEdge[] }

interface TopologyClassification {
  classification: "hub" | "spoke" | "shared-services" | "standalone" | "unknown";
  confidence: number;          // 0..1
  reasons: string[];
  hubId?: string;              // für Spokes
}

interface NvaClassification { potentialNva: boolean; confidence: number; reasons: string[] }
```

Zusätzlich zum Graph existiert `NormalizedInventory` (typisierte Listen: `vnets`, `subnets`, `peerings`, `routeTables`, `routes`, `nsgs`, `firewalls`, …) — exakt die Exportsektionen aus dem Lastenheft (§ 60). Graph und Inventory werden aus derselben Normalisierung erzeugt; Knoten-IDs = Resource-IDs, dadurch sind Inventory-Einträge und Graphknoten 1:1 verknüpft.

### 9.3 Beziehungen (Auszug)

| Edge | Von → Nach | Quelle |
| --- | --- | --- |
| `contains` | Subscription→Region→VNet→Subnet→NIC/PE | IDs |
| `peering` | VNet→VNet (gerichtet, pro Seite eine Kante; Symmetrie im Assessment) | `virtualNetworkPeerings` |
| `attached` | Subnet→RouteTable, Subnet→NSG, NIC→NSG, NIC→Subnet, NIC→VM | Referenzen |
| `natThrough` | Subnet→NAT GW, NAT GW→PIP/PIPP | `subnet.natGateway`, `natGateway.publicIpAddresses` |
| `nextHop` | Route→Ziel (FW/NVA/LB-Frontend/Gateway/Internet) | IP-Index-Auflösung von `nextHopIpAddress` |
| `securedBy` | VNet/Subnet→Firewall (abgeleitet aus Default-Route-Next-Hop) | Routing-Analyse |
| `internetEgress` | Subnet→Internet(ipv4/ipv6) mit `via` (Firewall/NAT/PIP/LB/Default) | Egress-Resolver |
| `privateEndpoint` | PE→Target-Ressource | `privateLinkServiceConnections` |
| `dnsLink` | Private-DNS-Zone→VNet | VNet-Links |
| `gatewayConnection` | Gateway→LNG/Circuit/Hub | `connections` |

---

## 10. IPv4/IPv6-Adressmodell & Klassifikation

- Eigene CIDR-Bibliothek auf `bigint` (IPv4 32 bit, IPv6 128 bit), ohne externe Abhängigkeit, vollständig getestet: Parsing (inkl. `::`-Kompression, IPv4-mapped), Normalisierung (Netzadresse, kanonische RFC-5952-Schreibweise), `contains`, `overlaps`, `lpm`.
- **IP-Index**: Intervallbaum pro Familie über alle Präfixe (VNet, Subnet, Peering-Remote, PIP, PIPP, LNG, ER) und Host-Adressen (NIC, FW, LB-Frontend, PE) → beantwortet die globale IP-Suche (§ 43) in O(log n).
- **Klassifikation** pro Ressource: aus `Addressing` abgeleitet; `unknown`, wenn die Quelle `not-accessible` ist. VNet-Klassifikation berücksichtigt Address Spaces; Subnet Prefixe; NIC IP-Konfigurationen (`privateIPAddressVersion`); NAT GW verbundene PIPs/PIPPs; Firewall IP-Konfigurationen.
- Zusätzliche Kennzeichen: `ULA (fc00::/7)`, `GUA`, `link-local`, `NAT64 (64:ff9b::/96)`, RFC1918, CGNAT (100.64/10) — relevant für Egress- und Sanitization-Logik.

---

## 11. Topologie: Hub/Spoke- und NVA-Erkennung

### 11.1 VNet-Klassifikation (gewichtete Heuristik, erklärbar)

Signale mit Gewichten (Startwerte, per Testfällen kalibriert):

| Signal | Richtung | Gewicht |
| --- | --- | --- |
| Peering-Grad ≥ 3 (Anteil an allen Peerings) | Hub | +0.25 (skaliert) |
| Azure Firewall / NVA / Route Server im VNet | Hub | +0.25 |
| VPN/ER-Gateway im VNet | Hub | +0.15 |
| `allowGatewayTransit=true` auf ausgehenden Peerings | Hub | +0.15 |
| Andere VNets routen `0.0.0.0/0` oder `::/0` auf eine IP in diesem VNet | Hub | +0.20 |
| `useRemoteGateways=true` | Spoke | +0.30 |
| Genau ein/wenige Peerings zu einem Hub-Kandidaten | Spoke | +0.25 |
| UDR-Default-Route zeigt auf IP in Hub-Kandidat | Spoke | +0.30 |
| Private DNS Resolver, Domain Controller-Tags, Bastion, zentrale PEs, viele Peerings ohne Gateway/Firewall | Shared Services | +0.2 je |
| Keine Peerings, kein vWAN-Hub-Anschluss | Standalone | 0.9 fix |
| Virtual-WAN-Hub-Connection | Spoke von virtualHub | 0.95 fix |

Algorithmus: (1) Hub-Kandidaten scoren, (2) Spokes relativ zu erkannten Hubs scoren, (3) Rest → Shared Services/Standalone/Unknown. `confidence = min(1, Σ Gewichte)`; `reasons[]` enthält jeden beitragenden Faktor als Klartext mit Zahlen. vWAN-Hubs (`virtualHub`) sind immer Hubs (Konfidenz 1.0).

### 11.2 NVA-Heuristik (VMs)
`enableIPForwarding` (+0.35), Ziel eines UDR-`VirtualAppliance`-Next-Hops (+0.40), ≥ 2 NICs in verschiedenen Subnets (+0.15), Marketplace-Image eines bekannten Firewall-Publishers (+0.20), Backend eines Internal-LB, der als UDR-Next-Hop dient (+0.30, HA-NVA-Pattern). `potentialNva = confidence ≥ 0.5`.

---

## 12. Routing-Analyse

### 12.1 Effective-Route-Synthese (pro Subnet und Adressfamilie)

Ohne Effective-Routes-API wird die Routing-Tabelle konfigurationsbasiert rekonstruiert:

1. **System-Routen**
   - `VnetLocal` für jedes VNet-Address-Space-Präfix der Familie.
   - `VNetPeering` für jeden `remoteVirtualNetworkAddressSpace` (bzw. `remoteAddressSpace`) verbundener Peerings mit `peeringState=Connected` und `allowVirtualNetworkAccess=true`; bei Subnet-Peering (`peerCompleteVnets=false`) nur die gepeerten Subnet-Präfixe.
   - Default: `0.0.0.0/0 → Internet`, `::/0 → Internet`; IPv4 zusätzlich RFC1918/100.64/10 → `None` (sofern nicht im Address Space).
   - Gateway-/BGP-Routen: **nicht aus Konfiguration ableitbar**. Erkennbar ist nur, *dass* ein Gateway erreichbar ist (lokales Gateway oder `useRemoteGateways`) und welche statischen Präfixe bekannt sind (LNG `localNetworkAddressSpace`, ER-Circuit-Peerings, vWAN). Diese werden als Routen mit `source="gateway-derived"` und Konfidenz `POSSIBLE` eingetragen; `disableBgpRoutePropagation=true` am Route Table unterdrückt sie.
   - vWAN-verbundene VNets: Routen aus Hub-Route-Tables / Routing Intent (Konfidenz `LIKELY`).
2. **UDRs** aus der zugeordneten Route Table (Next Hop `VirtualAppliance`, `VirtualApplianceEcmp`, `VirtualNetworkGateway`, `VnetLocal`, `Internet`, `None`).
3. **Auswahl**: Longest Prefix Match; bei gleicher Länge UDR > BGP > System (Azure-Regel).
4. Mit `--effective-routes` ersetzen die echten Effective Routes der NICs die Synthese (Konfidenz `CONFIRMED`); Abweichungen zwischen Synthese und Effective Routes werden als Info-Finding gemeldet (Hinweis auf BGP-Einflüsse).

### 12.2 Path Tracer

Eingabe: `source` (NIC, VM, Subnet, IP), `destination` (Ressource, IP, CIDR, `internet:ipv4`, `internet:ipv6`), Familie (bei Ressourcen-Zielen: jede verfügbare Familie).

Zustandsautomat mit Hop-Liste, max. 16 Hops, Zyklenerkennung:

```
Hop(Location) → Lookup effective route(destIP) →
  VnetLocal        → Ziel im selben VNet? → Delivered (NSG-Check Quelle-Out/Ziel-In)
  VNetPeering      → Remote-VNet; Ziel muss im Remote-Address-Space liegen (keine Transitivität) → weiter
  VirtualAppliance → IP-Index: Azure Firewall | NVA-NIC | ILB-Frontend (→ Backend-NVAs) | unbekannt
                     → Firewall: Regel-Evaluierung (best effort, siehe 12.3), SNAT/Egress der Firewall-Subnetz-Route
                     → weiter ab Subnet des Next Hops (dessen Route Table!)
  VirtualNetworkGateway → OnPremises / vWAN (Konfidenz nach Datenlage)
  Internet         → Egress-Resolver (12.4)
  None             → Dropped
```

Status des Pfades: `ALLOWED` | `BLOCKED` (NSG-Deny, Route `None`, Firewall-Deny) | `UNKNOWN` (fehlende Daten, BGP, unlesbare Policy) | `POTENTIAL_BYPASS` (Internet-Egress ohne Security-Hop, während die andere Adressfamilie oder vergleichbare Subnets über Firewall laufen).

Jeder Hop:

```ts
interface PathHop {
  index: number;
  nodeId: string;
  hopType: "source" | "subnet" | "udr" | "systemRoute" | "peering" | "firewall" | "nva" | "loadBalancer"
         | "natGateway" | "publicIp" | "gateway" | "internet" | "onPremises" | "destination" | "drop";
  family: IpFamily;
  reason: string;                    // z. B. "UDR ::/0 → VirtualAppliance fd00:10::4"
  routeTableId?: string;
  matchedRoute?: { prefix: string; nextHopType: string; nextHopIp?: string; source: "udr" | "system" | "gateway-derived" | "effective" };
  nsgDecision?: { nsgId: string; ruleName: string; direction: "in" | "out"; access: "Allow" | "Deny" };
  evidence: Evidence[];
  confidence: Confidence;
}
```

### 12.3 Security-Auswertung im Pfad
- **NSG**: vollständiger Evaluator (Priorität, Default Rules, Service Tags `Internet`, `VirtualNetwork`, `AzureLoadBalancer`; ASGs über NIC-Mitgliedschaft). Service Tags außer diesen drei → Konfidenz `LIKELY` (Präfixlisten nicht abgefragt).
- **Azure Firewall**: Regelmodell aus Policy-Hierarchie (Parent → Child, RCG-Priorität, Collection-Priorität; DNAT → Network → Application). Evaluierung für IP-/Port-Ziele; FQDN-/Application-Regeln → `LIKELY`/`POSSIBLE`. IP-Groups werden aufgelöst. Nicht lesbare Policy → `UNKNOWN` mit Evidence `missing-data`.
- Die Firewall wird primär als **Kontrollpunkt** bewertet („Pfad läuft durch Firewall ja/nein"); die Regelsemantik verfeinert, ersetzt aber nicht diese Aussage.

### 12.4 Egress-Resolver (pro Subnet, NIC und Familie)
Reihenfolge nach Azure-Dokumentation: UDR → VirtualAppliance/Gateway ≫ NAT Gateway (nur wenn SKU die Familie unterstützt: IPv6 nur `StandardV2` mit IPv6-PIP/PIPP) ≫ Instance-Level-PIP der Familie ≫ LB-Outbound-Rule mit Frontend der Familie ≫ Default Outbound Access (nur IPv4 und nur wenn `defaultOutboundAccess != false`; IPv6: Verhalten in Phase 9 gegen Doku verifizieren, bis dahin `UNKNOWN`).
Ergebnis: `EgressPath { family, mechanism: "firewall"|"nva"|"natGateway"|"instancePublicIp"|"lbOutbound"|"defaultOutbound"|"forcedTunnel"|"none"|"unknown", controlled: boolean, publicIps[], evidence[] }`.

---

## 13. Dual-Stack-Gap-Analyse

### 13.1 Matrix
Pro VNet und Subnet wird eine `DualStackMatrix` erzeugt; jede Zeile hat für beide Familien einen Wert **und** Evidence:

| Zeile | Quelle |
| --- | --- |
| VNet Address Space | VNet |
| Subnet Prefix | Subnet |
| NICs konfiguriert (n/m) | NIC-IP-Configs |
| NSG wirksam / Regeln familien-spezifisch | NSG-Evaluator (Regeln mit IPv4-/IPv6-Präfixen, `*`, Service Tags) |
| Default Route (Präfix → Next Hop) | Routing-Synthese |
| Zentrale Firewall im Pfad | Path Tracer zu `internet:<family>` |
| NAT Gateway (SKU-Fähigkeit) | NAT-GW + PIP-Familien |
| Internet Egress (Mechanismus, kontrolliert?) | Egress-Resolver |
| Internet Ingress (Public IPs, LB/AppGW-Frontends, DNAT) | Exposure-Analyse |
| Peering (Remote Address Space der Familie vorhanden) | Peerings |
| Gateway (Präfixe/BGP der Familie) | VPN/ER |
| DNS (A vs. AAAA-Records, die in dieses Subnet zeigen) | DNS-Records |
| Monitoring (Flow Logs/Diagnostic Settings auf den Kontrollpunkten) | Enrichment |

### 13.2 Gap-Erkennung
Eine Gap entsteht, wenn eine Zeile für die „Referenzfamilie" (typischerweise IPv4) einen **kontrollierten** Zustand hat und die andere Familie **existiert** (Adressen vorhanden), aber einen schwächeren Zustand. Existiert die zweite Familie nicht, entsteht kein Security-Gap, sondern höchstens ein `ADDRESSING_GAP` (Info). Gap-Typen gemäß Lastenheft (`ADDRESSING_GAP` … `HIGH_AVAILABILITY_GAP`).

### 13.3 Readiness pro Kategorie
`Addressing | Routing | Security | Egress | Ingress | DNS | Monitoring` → `READY | PARTIAL | NOT_READY | CRITICAL_GAP | UNKNOWN`, jeweils mit `evidence[]` und den zugrunde liegenden Gap-IDs. Regeln: kritisches Gap → `CRITICAL_GAP`; fehlende Daten in einer Kategorie → `UNKNOWN` (nie `READY`); gemischt → `PARTIAL`. **Kein Gesamtscore.**

---

## 14. Assessment Engine

```ts
interface AssessmentRule {
  id: string;                         // "NET-IPV6-003"
  category: Category;
  defaultSeverity: Severity;
  title: string;
  evaluate(ctx: AssessmentContextData): RuleResult[];   // pure Funktion, deterministisch
}

interface Finding {
  id: string;                         // stabil: `${ruleId}:${hash(sorted affectedResourceIds)}`
  ruleId: string;
  category: Category;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: Confidence;
  title: string;
  description: string;
  affectedResources: string[];
  evidence: Evidence[];
  recommendation: string;             // Text, niemals ausführbare Aktion
  references?: string[];              // Microsoft-Learn-URLs
  gapType?: GapType;
}
```

- **Stabile Finding-IDs** sind Voraussetzung für den Finding-Lifecycle im Snapshot-Vergleich.
- Severity-Kontext: z. B. NET-IPV6-003 ist `HIGH`, wird `CRITICAL`, wenn betroffene NICs öffentliche IPv6-Adressen oder NSG-Allow `Internet`/`::/0` inbound haben.
- Confidence-Degradierung: Jede Regel prüft, ob ihre Eingaben `accessStatus != ok` haben → Konfidenz `POSSIBLE`/`UNKNOWN` + Evidence `missing-data`.
- Regelkatalog (Start, vollständig in `ASSESSMENT-RULES.md`): NET-IPV6-001…015 (alle Punkte aus Lastenheft § 51), NET-ROUTE-001…, NET-PEER-001 (Asymmetrie, Disconnected, fehlender Remote-IPv6-Space), NET-FW-001, NET-NAT-001…003 (Public IPv6 an Workload, Standard-SKU mit IPv6-Subnet), NET-NSG-001…, NET-DNS-001, NET-HA-… (Firewall ohne Zonen, NAT Standard zonal), NET-MON-… (Firewall ohne Diagnostic Settings), NET-GOV-… (Subnets ohne NSG, Default Outbound aktiv).
- **ArchitectureGaps** aggregieren Findings über mehrere Ressourcen zu Aussagen auf Architekturebene (z. B. „IPv6 in Workload-VNets ohne zentralen IPv6-Sicherheitspfad").
- **AssessmentContext** (§ 62 Lastenheft) wird aus Topologie, Egress-Pfaden und Gaps erzeugt und ist Teil jedes Exports.

---

## 15. Discovery Quality & Warnings

```ts
interface DiscoveryWarning { resource?: string; scope?: string; operation: string; reason: "InsufficientPermissions" | "Throttled" | "NotFound" | "Truncated" | "TenantTokenUnavailable" | "Error"; detail?: string }
interface DiscoveryQuality {
  tenants: { total: number; readable: number };
  subscriptions: { total: number; readable: number };
  networkResources: number;
  argQueries: { executed: number; pages: number; truncated: number; failed: number };
  armEnrichment: { attempted: number; successful: number; unavailable: number };
  overallConfidence: "HIGH" | "MEDIUM" | "LOW";   // regelbasiert aus obigen Quoten, dokumentiert
}
```

---

## 16. Snapshot, Drift & Baseline

### 16.1 Snapshot = Export
Jeder JSON-Export ist ein Snapshot (`schemaVersion`, `snapshotMetadata`, vollständiges normalisiertes Inventory, Graph, Analyse, Findings). Import validiert per Zod, migriert ältere `schemaVersion`s (Migrationskette) und berechnet Analyse/Assessment neu, wenn die Regelversion abweicht (beide Ergebnisse werden angezeigt).

### 16.2 configurationHash
SHA-256 (Web Crypto, isomorph) über eine **kanonische Serialisierung** des normalisierten Inventories:
- Objekt-Keys sortiert, Arrays nach stabiler ID bzw. Inhalt sortiert, Resource-IDs lowercase.
- Ausgeschlossen (volatil): `provisioningState`, `etag`, `resourceGuid`, Zeitstempel, `generatedAt`, `snapshotId`, `peeringSyncLevel`-Übergangszustände, Discovery-Statistiken, Findings (werden separat als `findingsHash` gehasht).
- Tags fließen in einen separaten `tagsHash` ein, damit Tag-Änderungen die Architektur-Identität nicht verändern, aber sichtbar bleiben.

### 16.3 Semantic Diff
1. **Ressourcen-Match** über normalisierte Resource-ID; Fallback (bei Sanitization bzw. Re-Deployment) über `(type, subscription-pseudonym, name)`.
2. **Typ-spezifische Differ** vergleichen fachliche Felder (nicht JSON-Pfade): VNet (Address Spaces je Familie), Subnet (Präfixe, NSG/RT/NAT-Zuordnung), Route Table (Routen nach Präfix gematcht → Next-Hop-Änderungen), NSG (Regeln nach Name, zusätzlich semantisch: effektiv geöffnete Exposure), Firewall/Policy (Regeln nach Collection/Name; „relaxed" = Menge erlaubter Tupel wächst), Peering (Flags), NAT (SKU, PIP-Familien), PIP, DNS, Gateways.
3. **Abgeleitete Änderungen**: Vergleich der Default-Pfade/Egress-Pfade pro Subnet und Familie → „Firewall bypass introduced", „IPv6 bypass introduced", „Default Route changed to Internet", „NAT Gateway removed".
4. **Klassifikation**: `INFORMATIONAL | EXPECTED | SECURITY_RELEVANT | ARCHITECTURE_RELEVANT | POTENTIALLY_BREAKING` über eine Regeltabelle (z. B. Tag → INFORMATIONAL; Subnet+ → ARCHITECTURE_RELEVANT; NSG allow `::/0` inbound → SECURITY_RELEVANT; Default-Route-Next-Hop geändert → POTENTIALLY_BREAKING). `EXPECTED` wird gesetzt, wenn eine Änderung eine Baseline-Abweichung auflöst.
5. **Finding-Lifecycle** über stabile Finding-IDs: `NEW`, `RESOLVED`, `EXISTING`, `CHANGED` (Severity/Confidence/Evidence geändert). Zusätzlich „Architecture Improvement", wenn ein Change mindestens ein Finding auflöst und keins einführt (Akzeptanztest 4).

### 16.4 Baseline & Timeline
Ein Snapshot kann als `approvedBaseline` markiert werden (Flag + Metadaten in einer separaten Baseline-Datei, Snapshot selbst bleibt unverändert und hash-stabil). Timeline = sortierte Folge von Snapshots mit zusammengefassten Diff-Highlights.

---

## 17. Exporte

| Export | Erzeugung | Hinweise |
| --- | --- | --- |
| `azure-network-assessment-YYYYMMDD-HHMM.json` | `export/json` | Struktur exakt nach Lastenheft § 60 + `warnings`, `discoveryQuality`, `schemaVersion`; KI-freundlich: nur normalisierte Felder, keine ARM-Rohdaten |
| `azure-network-diff-YYYYMMDD-HHMM.json` | `export/diff` | Struktur nach § 78 |
| `.drawio` | `export/drawio` | unkomprimiertes `mxfile`/`mxGraphModel`-XML; Positionen aus derselben ELK-Layout-Pipeline; Layer (`mxCell parent="0"`): Azure Architecture, IPv4, IPv6, Routing, Security, Assessment Findings; Kantenstile je Beziehungstyp; Azure-Shapes aus der eingebauten diagrams.net-Bibliothek (`img/lib/azure2/...`) |
| SVG | CLI: aus Layout direkt; UI: aus React Flow | |
| PNG | UI (`html-to-image`) | CLI-PNG nicht vorgesehen (keine Headless-Browser-Abhängigkeit) |
| CSV | `export/csv` | Ressourcen-Inventar |

### 17.1 Sanitization
- Deterministische Pseudonyme via HMAC-SHA-256 mit Schlüssel (`--sanitize-key` bzw. zufällig pro Export). Gleicher Schlüssel ⇒ vergleichbare sanitisierte Snapshots.
- Tenant-/Subscription-IDs → pseudonyme GUIDs; Resource-Namen → `<typ>-<hash8>`; Resource-IDs werden konsistent umgeschrieben (Beziehungen bleiben erhalten).
- Öffentliche IPs/Präfixe → **präfixerhaltende** Abbildung in Dokumentationsbereiche (IPv4 `198.18.0.0/15`, IPv6 `2001:db8::/32`), sodass Containment und Präfixlängen erhalten bleiben. Private Adressen (RFC1918, ULA) bleiben standardmäßig erhalten (Routinglogik), optional ebenfalls präfixerhaltend umschreibbar.
- Blocklist-Filter entfernt unabhängig vom Sanitize-Flag immer: Shared Keys (`connections.sharedKey`), Zertifikate (AppGW `sslCertificates.data`, `trustedRootCertificates`), `keyVaultSecretId`-Werte, Connection-Strings, SAS-Token, P2S-Root-Zertifikate. Normalizer übernehmen diese Felder nie; der Filter ist zweite Verteidigungslinie.

---

## 18. UI-Architektur

- **Stack**: React 19, Vite 8, `@xyflow/react` 12, `elkjs` im Web Worker, Zustand, TanStack Virtual (Tree/Listen), CSS-Custom-Properties als Theme-Tokens (`--network-ipv4`, `--network-ipv6`, `--network-dualstack`, `--network-warning`, `--network-critical`, `--network-hub`, `--network-spoke`, Light/Dark).
- **Layout**: Drei Spalten — Tree View (links, virtualisiert), Topologie (Mitte, Mini-Map, Zoom, Fit View, Breadcrumb), Detail Panel (rechts). Dashboard, Findings, Path Trace, Compare, Drift als Tabs.
- **Levels of Detail 1–5** gemäß Lastenheft; Knoten tragen `lod`, sichtbar ist `lod ≤ aktuelles Level` **und** expandierte Container. Subscriptions/Regionen als ELK-Compound-Nodes (Cluster), Hub zentral durch Layout-Constraints (Hub-Knoten mit höherer Priorität, `elk.layered` für Hub→Spoke, `elk.force`/`stress` alternativ).
- **Performance**: Layout wird gecacht pro (Graph-Hash, LOD, Expand-Set, Filter) und nur bei strukturellen Änderungen neu berechnet; Selektion/Hover ändern kein Layout. `onlyRenderVisibleElements`, memoisierte Node-Komponenten, Aggregationskanten zwischen kollabierten Clustern (verhindert Spaghetti).
- **IP-Modi** `IPv4 | IPv6 | Dual Stack | Compare`: steuern Knotenfarbe, sichtbare Adressen, Routing-Kanten (`family`), im Compare-Modus Split-Darstellung der Pfade.
- **Tree ↔ Graph-Synchronisation** über gemeinsame `selectedNodeId` im Store; Tree-Klick expandiert Vorfahren im Graph und fokussiert (`fitView({ nodes })`).
- **Suche**: Worker mit Namens-/ID-Index und IP-Index; IP/CIDR-Eingaben werden erkannt und liefern VNet, Subnet, NIC, PIP, Prefix und die mögliche Route (Path-Trace-Shortcut).

### 18.1 Anmeldung & Datenzugriff in der UI
Statische SPA ohne Backend. `MsalProvider` umschließt die App; ohne Anmeldung sind nur Snapshot-Import und Offline-Analyse verfügbar. Nach Anmeldung: Tenant-Auswahl (aus `tenants.list`) → Discovery im Browser (Web Worker für Normalisierung/Analyse, Progress-Anzeige) → Ergebnis im Store. Der Discovery-Cache liegt nur im Arbeitsspeicher des Tabs (nur Ressourcendaten, keine Tokens) und wird beim Abmelden verworfen.

---

## 19. CLI

```
npm run discover -- [--tenant <id>] [--subscription <id>...] [--credential default|cli|vscode|mi|workload] [--out output/]
npm run assess   -- --input output/network-inventory.json
npm run export   -- --input <snapshot.json> --format json|drawio|svg|csv [--sanitize [--sanitize-key <k>]]
npm run snapshot -- [discover-Flags]                         # discover + assess + snapshot in einem Schritt
npm run diff     -- --from <a.json> --to <b.json> [--baseline]
npm run dev | npm run build && npm run preview               # Web-UI (MSAL-Anmeldung)
```
Ausgabe: `output/network-inventory.json`, `output/network-assessment.json` (Snapshot), `output/network-topology.drawio`. Exit-Codes: 0 ok, 2 Discovery unvollständig (Warnungen), 1 Fehler.

---

## 20. Logging

Strukturiert (JSON Lines, Level `debug|info|warn|error`), Events: `discovery.start`, `subscriptions.discovered`, `arg.query`, `arg.page`, `arm.enrichment`, `normalization`, `graph.build`, `routing.analysis`, `dualstack.analysis`, `assessment`, `snapshot`, `export`. Felder: `ts`, `level`, `event`, `durationMs`, `counts`, `scope` (Subscription-IDs, keine Tokens). Redaction-Filter vor jedem Write.

---

## 21. Risiken & technische Einschränkungen

| # | Risiko / Einschränkung | Auswirkung | Gegenmaßnahme |
| --- | --- | --- | --- |
| R1 | **BGP-/Gateway-Routen** sind nicht in der Konfiguration sichtbar (VPN/ER/Route Server/vWAN propagieren dynamisch, z. B. `0.0.0.0/0` via ER = Forced Tunneling). | Routing-Aussagen können falsch-sicher sein. | Gateway-abgeleitete Routen als `POSSIBLE`; Pfade mit Gateway-Einfluss → Status `UNKNOWN`; optional Effective Routes (Custom Role). |
| R2 | Effective Routes/NSG benötigen Actions außerhalb von *Reader* und sind POST. | Keine Laufzeitwahrheit im Standardmodus. | Optionales Feature, Allowlist, dokumentiert. |
| R3 | ARG-Indexierung ist eventual consistent; ARG kann sehr große Property-Bags kürzen. | Kleine Zeitverzüge / unvollständige Regeln. | `snapshotMetadata.indexLagNotice`; Plausibilitätsprüfungen (z. B. RCG-Referenzen vs. Treffer) → ARM-Fallback. |
| R4 | ARG-Throttling (Quota pro Benutzer und Zeitfenster). | Lange Laufzeiten in großen Tenants. | Header-gesteuertes Drosseln, Batching, Cache, Projektion. |
| R5 | Azure-Firewall-Regelauswertung (FQDN, Web Categories, TLS-Inspection, IDPS) ist nicht vollständig statisch berechenbar. | Allow/Deny für FQDN-Ziele unsicher. | Firewall primär als Kontrollpunkt bewertet; Regelergebnis mit Konfidenz. |
| R6 | Third-Party-NVAs: Konfiguration unsichtbar. | Pfad endet in „NVA, Verhalten unbekannt". | NVA-Heuristik + Status `UNKNOWN` ab NVA. |
| R7 | Service Tags (außer `Internet`, `VirtualNetwork`, `AzureLoadBalancer`) werden nicht in Präfixe aufgelöst. | NSG-Bewertung für Service-Tag-Regeln unscharf. | Konfidenz `LIKELY`; optional später Service-Tag-Discovery-API (GET). |
| R8 | IPv6-Default-Outbound-Verhalten und einige IPv6-Einschränkungen (z. B. Firewall-IPv6-Unterstützung, Gateway-IPv6) ändern sich laufend. | Veraltete Annahmen. | Alle feature-abhängigen Aussagen in einer versionierten `capabilities`-Tabelle mit Quellen-URL; Verifikation in Phase 9/10 via Microsoft Learn. |
| R9 | Multi-Tenant-Tokens scheitern an MFA/Conditional Access. | Tenants fehlen. | Warnung `TenantTokenUnavailable`, Discovery-Quality sichtbar. |
| R10 | Sehr große Graphen (≥ 10 000 Knoten) im Browser. | Layout-/Renderzeit. | LOD, Cluster, Worker-Layout, Layout-Cache, Virtualisierung. |
| R11 | Azure Virtual Network Manager kann Konnektivität (Mesh) und Security Admin Rules außerhalb von Peerings/NSGs definieren. | Falsche Pfad- und Bypass-Aussagen, wenn AVNM ignoriert wird. | AVNM-Daten aus `networkresources` in Routing- und Security-Evaluator; ohne Daten Konfidenz nicht `CONFIRMED`. |
| R12 | TypeScript 7 noch nicht von typescript-eslint unterstützt. | Toolchain-Bruch. | TS 6.0.x pinnen. |
| R13 | Browser-Tokens (XSS, Supply-Chain im Frontend) mit `user_impersonation` können mehr als lesen, wenn der Benutzer Schreibrechte hat. | Missbrauch des Tokens außerhalb der App. | Strikte CSP, keine Inline-Skripte, `sessionStorage`-Cache, Abhängigkeiten gepinnt + `npm audit`, Empfehlung: Konten nur mit `Reader`, Enterprise App mit „Assignment required“ und Conditional Access. |
| R15 | SPA-Refresh-Tokens gelten nur 24 h; Third-Party-Cookie-Blocking verhindert Silent Renew im iframe. | Erneute Anmeldung während langer Sitzungen. | `acquireTokenSilent` → bei `InteractionRequiredAuthError` Popup; Discovery ist wiederaufnehmbar (Cache). |
| R14 | Definition of Done verlangt reale Azure-Tests. | CI kann das nicht leisten. | Automatisierte Tests mit Fixtures; manuelle Abnahme-Checkliste gegen realen Tenant (`docs/ACCEPTANCE.md`), plus optionaler `npm run test:live` (read-only, nur aggregierte Assertions). |
