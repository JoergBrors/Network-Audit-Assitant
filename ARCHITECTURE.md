# ARCHITECTURE — Azure Network Audit Assistant

Status: freigegeben (Phase 2), fortgeschrieben 2026-09-25 nach Review · Export-Schema aktuell `0.6.0` (1.0.0 nach Abschluss der Analysephasen) · Umsetzungsstand je Phase: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)

Kennzeichnung in diesem Dokument: **[umgesetzt]**, **[teilweise]**, **[geplant]**.

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
| `@azure/arm-network` | 39.0.0 | `2026-01-01` | Enrichment-GETs (installiert, Nutzung ab Phase 5) |
| `@azure/arm-resources-subscriptions` | 3.0.0 | `2022-12-01` | Tenants/Subscriptions (`tenants.list`, `subscriptions.list`) |
| `@azure/msal-browser` | 5.23.0 | – | Anmeldung der Web-UI (Auth Code + PKCE) |
| `@azure/arm-cdn` | 10.0.0 | `2025-12-01` | Front Door Standard/Premium (Origins, Routes) – installiert, Nutzung ab Phase 5 |
| `@xyflow/react` | 12.12.0 | – | Topologie |
| `elkjs` | 0.12.0 | – | Layout (`elk-api` + `elk-worker.min.js`) |
| `zod` | 4.6.5 | – | Schema/Validierung |
| `vitest` | 5.0.1 | – | Tests |

Nicht installiert, weil nicht benötigt: `@azure/arm-privatedns` und `@azure/arm-dnsresolver` (Records und Resolver-Kinder liefert ARG), `@azure/msal-react`, Zustand.

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

```text
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

**[umgesetzt]** `src/azure/http/readOnlyGuardPolicy.ts`, ESLint-Regel, Tests inkl. echter SDK-Clients.

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
  - `redirectUri` = `<origin>/redirect.html` **[umgesetzt]**: MSAL v5 verlangt eine eigene **Redirect-Bridge-Seite**, die nur `broadcastResponseToMainFrame()` ausführt und die Antwort an das Hauptfenster weiterreicht (`redirect.html` + `src/auth/browser/redirectBridge.ts`, als eigene Vite-Seite gebaut). Zeigt die Redirect-URI auf die App selbst, scheitert die Anmeldung mit `no_token_request_cache_error`. `postLogoutRedirectUri` = Startseite.
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

```text
src/
  auth/
    browser/            [umgesetzt] MSAL-Konfiguration, MsalTokenCredential, Session (Login/Logout), Redirect-Bridge
    node/               [umgesetzt] DefaultAzureCredential & Co.
    tenantCredential.ts [umgesetzt] tenant-gebundener TokenCredential-Wrapper
  azure/
    http/               [umgesetzt] readOnlyGuardPolicy, ARG-Quota-Drossel, Client-Optionen (SDK-Retry)
    subscriptions/      [umgesetzt] Tenants, Subscriptions (Lighthouse-Deduplizierung)
    resourceGraph/      [umgesetzt] Query-Katalog (queries.ts), Runner (Paging, Batching, Split, Cache), Client
    arm/                [geplant]   Enrichment-Plan & Clients (Phase 5)
    cache.ts, errors.ts [umgesetzt] Cache-Interface/MemoryCache, Fehlerklassifikation
  discovery/            [umgesetzt] Orchestrierung → RawInventory, DiscoveryQuality, Warnungen/Hinweise
  models/               [umgesetzt] discovery.ts (Zod), graph.ts (Zod), network.ts (TS-Interfaces)
  normalization/        [umgesetzt] Raw → NormalizedInventory, generische/unklassifizierte Ressourcen
  addressing/           [teilweise] Familie, bigint-CIDR, Containment, Klassifikation
  graph/                [umgesetzt] buildGraph.ts (Knoten/Kanten/LOD), view.ts (Sichtbarkeit, Filter, Kanten-Lifting)
  topology/             [umgesetzt] Hub/Spoke/Shared/Standalone, NVA-Heuristik
  pipeline/             [umgesetzt] analyze.ts: Normalisierung → Klassifikation → Graph (NetworkModel)
  drift/                [teilweise] semantischer Diff, Drift-Kategorien, Vergleichsgraph, Diff-Export
  export/               [teilweise] assessmentJson.ts (Export/Import); Draw.io/CSV/SVG/Sanitizer geplant
  routing/              [geplant]   Effective-Route-Synthese, LPM, Path-Tracer, Egress-Resolver (Phase 9)
  security/             [geplant]   NSG-/Firewall-Evaluator, Exposure (Phase 9)
  dualstack/            [geplant]   Matrix, Gaps, Readiness (Phase 10)
  assessment/           [geplant]   Rule-Engine, Regelkatalog, ArchitectureGaps (Phase 11)
  snapshots/            [geplant]   configurationHash, Baseline, Migration (Phase 12)
  logging/              [umgesetzt] JSON Lines, Redaction
  utils/                [umgesetzt] Concurrency, Resource-ID-Helfer
  cli/                  [teilweise] `discover`, Datei-Cache
  ui/                   [teilweise] React-App (Vite)
    App.tsx             Anmeldung, Discovery, Export/Import, Vergleich
    components/         Discovery-Übersicht
    graph/              TopologyView (React Flow), Knoten, ELK-Graph, LayoutClient
    workspace/          Workspace, TreeView, DetailPanel, SearchBox, Changes (Vergleich), Download
    theme/              CSS-Tokens (Light/Dark), Layout-CSS
tests/                  [umgesetzt] Unit-/Integrationstests je Modul
  fixtures/             synthetisches Hub-and-Spoke-Szenario im ARG-Format (keine Tenantdaten)
scripts/                [umgesetzt] verify-arg-coverage.ts
redirect.html           [umgesetzt] MSAL-Redirect-Bridge
```

**Abhängigkeitsregel (erzwungen):** `ui` → `core`-Module; `core` (`models`…`export`) → keine Imports aus `azure`, `auth`, `cli`, `ui`, keine Node-Builtins. `azure`/`discovery` → `models`, `utils`, `logging`, keine Node-Builtins (Cache-Adapter werden injiziert). `auth/browser` nur aus `ui`, `auth/node` nur aus `cli`.

---

## 7. Discovery-Strategie (Azure Resource Graph first)

**[umgesetzt]** mit folgenden Abweichungen: Retry/Backoff über die SDK-Retry-Policy; Management-Group-Abfrage ist optional und erzeugt bei Fehlern nur Hinweise (`warning.optional = true`), die die Konfidenz nicht senken.

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

**[teilweise]** (Phase 5). Umgesetzt in `src/azure/arm`: GET-only-`ArmReader` (Read-only-Guard, Retry, Token je Tenant, `nextLink`) und `runEnrichment` für vWAN-Hub-Details (E-VWAN-01…03) sowie Service-Tag-Präfixe (E-SVC-01, nur referenzierte Tags). Jeder Aufruf ist isoliert; 403/Fehler werden zu `EnrichmentResult` und Warnung, die Analyse senkt dann die Konfidenz (vWAN-Routen POSSIBLE statt LIKELY, nicht auflösbare Tags → UNKNOWN/POSSIBLE). Offen: Front Door, Diagnostic Settings, Fallbacks, Cache, Effective Routes.

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

Keine UI-Komponente sieht Rohdaten. **Ist-Stand:** Discovery- und Graph-Typen sind Zod-Schemas (`src/models/discovery.ts`, `src/models/graph.ts`); das normalisierte Inventar ist als TypeScript-Interfaces modelliert (`src/models/network.ts`), der Import prüft es strukturell. Die verbindliche Beschreibung des implementierten Modells steht in [NETWORK-GRAPH-MODEL.md](NETWORK-GRAPH-MODEL.md). Die folgenden Abschnitte beschreiben das **Zielmodell**; noch nicht umgesetzt sind `Evidence`, `Confidence`, `accessStatus`, `security`/`routing`-Zusammenfassungen und `findingIds` am Knoten (kommen mit Phasen 9–11).

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

### 9.2 NetworkGraph (Zielmodell; implementierte Typen siehe NETWORK-GRAPH-MODEL.md)

Abweichungen der Implementierung: Peerings, IP-Konfigurationen, NSG- und Firewall-Regeln sind keine eigenen Knoten, sondern Kanten bzw. Tabellen im Inventar; zusätzlich gibt es `externalResource` (nicht lesbare Ziele), `networkWatcher`, `flowLog`, `other`. Kantentypen `nextHop`/`associatedPublicIp` heißen `route`/`attached`; neu ist `monitoredBy`.

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

**[teilweise]** Umgesetzt: Familienerkennung, bigint-Parsing (inkl. `::`-Kompression, IPv4-mapped), Containment, Klassifikation, Default-Route-Erkennung (`src/addressing/ip.ts`); die Suche nutzt Containment. Offen: RFC-5952-Normalisierung, Overlap, IP-Index, Adresskategorien.

- Eigene CIDR-Bibliothek auf `bigint` (IPv4 32 bit, IPv6 128 bit), ohne externe Abhängigkeit, vollständig getestet: Parsing (inkl. `::`-Kompression, IPv4-mapped), Normalisierung (Netzadresse, kanonische RFC-5952-Schreibweise), `contains`, `overlaps`, `lpm`.
- **IP-Index**: Intervallbaum pro Familie über alle Präfixe (VNet, Subnet, Peering-Remote, PIP, PIPP, LNG, ER) und Host-Adressen (NIC, FW, LB-Frontend, PE) → beantwortet die globale IP-Suche (§ 43) in O(log n).
- **Klassifikation** pro Ressource: aus `Addressing` abgeleitet; `unknown`, wenn die Quelle `not-accessible` ist. VNet-Klassifikation berücksichtigt Address Spaces; Subnet Prefixe; NIC IP-Konfigurationen (`privateIPAddressVersion`); NAT GW verbundene PIPs/PIPPs; Firewall IP-Konfigurationen.
- Zusätzliche Kennzeichen: `ULA (fc00::/7)`, `GUA`, `link-local`, `NAT64 (64:ff9b::/96)`, RFC1918, CGNAT (100.64/10) — relevant für Egress- und Sanitization-Logik.

---

## 11. Topologie: Hub/Spoke- und NVA-Erkennung

**[umgesetzt]** in `src/topology/classify.ts`. Die tatsächlich verwendeten Gewichte und Schwellen stehen in [NETWORK-GRAPH-MODEL.md § 5](NETWORK-GRAPH-MODEL.md); die Tabelle unten war der Startentwurf.

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

**[teilweise]** Umgesetzt in `src/routing` und `src/security` (Details unten und in § 12.5): Routen-Synthese je Subnet und Familie, Routenauswahl, Path Tracer mit Hop-Evidence, NSG- und Firewall-Policy-Auswertung, Egress-Resolver, IPv4/IPv6-Vergleich, tenantweite Default-Pfad-Analyse, UI (Pfadanalyse, Internet-Pfade, effektive Routen) und Export. Zusätzlich: eingehende Pfade Internet → Workload, Virtual-WAN-Routing, AVNM (Security Admin Rules, Connected Groups), ECMP und Service-Tag-Präfixe. Offen: Effective-Routes-API (optional), vWAN Branch-/Hub-zu-Hub-Routing.

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

```text
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

### 12.5 Umsetzung und belegte Plattformregeln (Stand 2026-09-25)

| Regel | Quelle | Umsetzung |
| --- | --- | --- |
| Longest Prefix Match; bei gleicher Länge UDR > BGP > System; VNet-/Peering-Systemrouten gewinnen auch gegen spezifischere BGP-Routen | Microsoft Learn: *Virtual network traffic routing* | `selectRoute` |
| Default-Systemrouten: Adressraum → VNet, `0.0.0.0/0` → Internet, RFC1918/100.64/10 und weitere reservierte Bereiche → None; None entfällt bei Überlappung mit dem Adressraum und bei `0.0.0.0/0` → Gateway | ebenda | `synthesizeRoutes` (None-Routen Konfidenz LIKELY) |
| IPv6: `::/0` → Internet als System-Default | in der Doku nicht explizit tabelliert | Konfidenz LIKELY |
| Per BGP gelernte Routen (VPN/ER/Route Server) sind in der Konfiguration nicht sichtbar | – | Gateway-Routen aus Local Network Gateways (POSSIBLE); System-Default POSSIBLE, wenn BGP-Gateways erreichbar und Propagation aktiv |
| Egress-Vorrang: UDR zu Appliance/Gateway > NAT Gateway > Instance-PIP > LB-Outbound > Default Outbound | Microsoft Learn: *NAT Gateway overview* | `resolveEgress` |
| NAT Gateway Standard nur IPv4; IPv6 nur StandardV2 | Microsoft Learn: *NAT Gateway SKUs* | Evidence im Egress |
| Default Outbound nur für nicht-private Subnets; neue VNets seit 31.03.2026 privat; für IPv6 nicht dokumentiert | Microsoft Learn: *Default outbound access* | IPv4: `defaultOutbound`/`none`; IPv6 ohne explizite Methode: `unknown` |
| Azure Firewall IPv6 (Preview): nur Network Rules und DNS-Proxy; keine Application-/DNAT-Regeln, IP Groups, vHub-Firewall | Microsoft Learn: *Deploy Azure Firewall in dual stack mode* | Firewall-Evaluator ignoriert für IPv6 IP Groups und Application Rules, Evidence-Hinweis |
| VirtualAppliance-Next-Hop ohne IP-Forwarding an der NIC verwirft Pakete | Microsoft Learn: *Diagnose a VM routing problem* | Hop `drop` |
| UDRs mit Service Tags: bei gleichem Präfix gewinnt die exakte (spezifischere) Tag-Route; explizite CIDR-Routen gewinnen bei gleicher Länge | Microsoft Learn: *Virtual network traffic routing – Service tags for user-defined routes* | Expansion über Service-Tag-API, `tagRank` |
| ECMP: mehrere Next-Hop-IPs einer Route verteilen Flows | Route-Ressource `nextHop.nextHopIpAddresses` | Hop „ECMP (n Next Hops)“, alle Ziele als Kontrollen, Konfidenz POSSIBLE bei gemischten/unbekannten Zielen |
| AVNM Security Admin Rules vor NSG: Deny beendet, Always Allow liefert ohne NSG-Prüfung, Allow → NSG | Microsoft Learn: *Security admin rules in AVNM* | `checkSecurity` (neuester Rule-Snapshot je Regel, nur für die Konfiguration des VNets) |
| AVNM Connectivity (Mesh / Direct Connectivity) verbindet VNets ohne sichtbare Peerings | Microsoft Learn: *Connectivity configuration in AVNM* | Route `ConnectedGroup` (LIKELY) |
| Virtual WAN: Routing Intent (Private/Internet) überschreibt Route-Table-Logik; ohne Intent assoziierte Hub Route Table + Propagation; `enableInternetSecurity` steuert 0/0 | Microsoft Learn: *Virtual hub routing*, *Routing intent* | `virtualWanRoutes` (LIKELY, POSSIBLE ohne Hub-Details) |
| Virtual WAN und Secured-Hub-Firewall routen kein IPv6 | Microsoft Learn: *IPv6 in Virtual WAN* / Azure Firewall dual stack | keine vWAN-Routen für IPv6 |
| Azure Firewall DNAT übersetzt auch die Quelle auf eine private Firewall-IP; Antworten müssen über die Firewall zurück | Microsoft Learn: *Filter inbound Internet traffic with Azure Firewall DNAT* | Inbound-Prüfung mit Firewall-IP als Quelle |
| Eingang über Public IP/LB bei UDR 0/0 → Firewall erzeugt asymmetrisches Routing (Antworten werden verworfen) | Microsoft Learn: *Integrate Azure Firewall with Standard Load Balancer* | `asymmetricRouting`, Status UNKNOWN |

**Path Tracer** (`tracePath`):
- Quelle ist ein Subnet, eine NIC, eine VM, eine VM Scale Set oder ein Private Endpoint; Ziel ist das Internet (Stellvertreteradresse), eine IP oder eine Ressource.
- Reihenfolge: NSG ausgehend (NIC, dann Subnet), dann je Subnet die effektive Route.
- Je nach Next Hop:
  - VNet oder Peering: Zustellung mit NSG eingehend (Subnet, dann NIC)
  - Azure Firewall: Regelauswertung, SNAT, weiter aus dem Firewall-Subnet
  - NVA oder ILB: IP-Forwarding-Prüfung, weiter aus dem NVA-Subnet, Status höchstens UNKNOWN
  - Gateway: On-Premises bzw. Forced Tunneling
  - Internet: Egress-Resolver
- Schleifen werden erkannt, sowohl über wiederholte Subnets als auch über wiederholte Appliances.
- `POTENTIAL_BYPASS`, wenn Internetverkehr ohne Sicherheitskontrolle austritt, obwohl der Hub des VNets eine Firewall oder NVA hat.
- `compareFamilies` liefert Unterschiede und die „Architecture Gap“, wenn IPv4 kontrolliert und IPv6 unkontrolliert ist.

**Eingehende Pfade** (`analyzeInbound`, `src/routing/inbound.ts`):
- Eingänge: Instance-Public-IP an der NIC, Public Load Balancer (Regeln → Backend-Pool, Inbound NAT → NIC), Application Gateway (Listener → Backend-Pool; NSG sieht das AppGW-Subnet als Quelle; WAF = kontrolliert), Azure-Firewall-DNAT (Quelle = Firewall-IP, kontrolliert).
- Je Eingang: AVNM + NSG eingehend (Subnet, dann NIC) für die relevanten Ports; Instance-PIPs gegen eine Liste typischer Ports (22, 3389, 80, 443, 445, 1433, 3306, 5432, 5985, 5986, 8080).
- Ergebnis: offene Ports (beliebige Internet-Quelle), eingeschränkte Ports (nur explizite öffentliche Quellbereiche), Rückweg-Prüfung (asymmetrisches Routing), Status und Konfidenz.
- Export: `assessmentContext.internetIngressPaths` und Gaps `IPV6_INBOUND_EXPOSURE`, `UNCONTROLLED_INBOUND_EXPOSURE`, `ASYMMETRIC_INBOUND_ROUTING`.

**Realer Tenant** (aggregiert):
- 175 Subnet-Pfade in 31 ms
- 38 eingehende Pfade in 53 ms; 16 offen ohne zentrale Kontrolle, 14 mit asymmetrischem Rückweg
- 66 IPv4-Subnets über Azure Firewall
- 61 IPv4-Subnets in Spokes als potenzieller Bypass (keine Default-UDR, Default Outbound)
- 2 NICs mit IPv6-Firewall-Bypass über Instance-Public-IPv6

## 13. Dual-Stack-Gap-Analyse

**[geplant]** (Phase 10). Vorstufe umgesetzt: IP-Modi IPv4/IPv6/Dual Stack als Filter in der Topologie.

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

**[geplant]** (Phase 11).

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

**[umgesetzt]** (`src/models/discovery.ts`, `src/discovery/quality.ts`); `armEnrichment` bleibt bis Phase 5 bei 0.

```ts
interface DiscoveryWarning {
  resource?: string; scope?: string; operation: string;
  reason: "InsufficientPermissions" | "Throttled" | "NotFound" | "Truncated" | "TenantTokenUnavailable" | "SubscriptionDisabled" | "Error";
  detail?: string;
  optional?: boolean;   // optionale Daten (z. B. Management Groups): als Hinweis angezeigt, ohne Einfluss auf die Konfidenz
}
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

Details der Umsetzung: [SNAPSHOT-AND-DRIFT.md](SNAPSHOT-AND-DRIFT.md).

### 16.1 Snapshot = Export

**[teilweise]** Umgesetzt: Export trägt `snapshotMetadata`, Import validiert per Zod und baut den Graphen deterministisch aus dem Inventar neu auf. Geplant: Migrationskette, Neuberechnung der Assessments.

Jeder JSON-Export ist ein Snapshot (`schemaVersion`, `snapshotMetadata`, vollständiges normalisiertes Inventory, Graph, Analyse, Findings). Import validiert per Zod, migriert ältere `schemaVersion`s (Migrationskette) und berechnet Analyse/Assessment neu, wenn die Regelversion abweicht (beide Ergebnisse werden angezeigt).

### 16.2 configurationHash

**[geplant]** SHA-256 (Web Crypto, isomorph) über eine **kanonische Serialisierung** des normalisierten Inventories:

- Objekt-Keys sortiert, Arrays nach stabiler ID bzw. Inhalt sortiert, Resource-IDs lowercase.
- Ausgeschlossen (volatil): `provisioningState`, `etag`, `resourceGuid`, Zeitstempel, `generatedAt`, `snapshotId`, `peeringSyncLevel`-Übergangszustände, Discovery-Statistiken, Findings (werden separat als `findingsHash` gehasht).
- Tags fließen in einen separaten `tagsHash` ein, damit Tag-Änderungen die Architektur-Identität nicht verändern, aber sichtbar bleiben.

### 16.3 Semantic Diff

**[teilweise]** Umgesetzt sind 1 (Match über Resource-ID; ohne Namens-Fallback), 2 (generischer Feld-Diff auf dem normalisierten Modell; Listen mit `id`/`name` wie NSG-Regeln, Routen, Links werden je Element verglichen), 4 (Kategorien per Regeltabelle, ohne `EXPECTED`) sowie Beziehungsänderungen und Geister-Knoten für entfernte Ressourcen in der UI. Offen: 3 (abgeleitete Pfad-Änderungen, nach Phase 9), 5 (Finding-Lifecycle, nach Phase 11), Firewall-„relaxed“-Semantik.

1. **Ressourcen-Match** über normalisierte Resource-ID; Fallback (bei Sanitization bzw. Re-Deployment) über `(type, subscription-pseudonym, name)`.
2. **Typ-spezifische Differ** vergleichen fachliche Felder (nicht JSON-Pfade): VNet (Address Spaces je Familie), Subnet (Präfixe, NSG/RT/NAT-Zuordnung), Route Table (Routen nach Präfix gematcht → Next-Hop-Änderungen), NSG (Regeln nach Name, zusätzlich semantisch: effektiv geöffnete Exposure), Firewall/Policy (Regeln nach Collection/Name; „relaxed" = Menge erlaubter Tupel wächst), Peering (Flags), NAT (SKU, PIP-Familien), PIP, DNS, Gateways.
3. **Abgeleitete Änderungen**: Vergleich der Default-Pfade/Egress-Pfade pro Subnet und Familie → „Firewall bypass introduced", „IPv6 bypass introduced", „Default Route changed to Internet", „NAT Gateway removed".
4. **Klassifikation**: `INFORMATIONAL | EXPECTED | SECURITY_RELEVANT | ARCHITECTURE_RELEVANT | POTENTIALLY_BREAKING` über eine Regeltabelle (z. B. Tag → INFORMATIONAL; Subnet+ → ARCHITECTURE_RELEVANT; NSG allow `::/0` inbound → SECURITY_RELEVANT; Default-Route-Next-Hop geändert → POTENTIALLY_BREAKING). `EXPECTED` wird gesetzt, wenn eine Änderung eine Baseline-Abweichung auflöst.
5. **Finding-Lifecycle** über stabile Finding-IDs: `NEW`, `RESOLVED`, `EXISTING`, `CHANGED` (Severity/Confidence/Evidence geändert). Zusätzlich „Architecture Improvement", wenn ein Change mindestens ein Finding auflöst und keins einführt (Akzeptanztest 4).

### 16.4 Baseline & Timeline

**[geplant]** Ein Snapshot kann als `approvedBaseline` markiert werden (Flag + Metadaten in einer separaten Baseline-Datei, Snapshot selbst bleibt unverändert und hash-stabil). Timeline = sortierte Folge von Snapshots mit zusammengefassten Diff-Highlights.

---

## 17. Exporte

| Export | Erzeugung | Hinweise |
| --- | --- | --- |
| `azure-network-assessment-YYYYMMDD-HHMM.json` | `export/assessmentJson.ts` **[teilweise]** | Struktur nach Lastenheft § 60 + `discovery` (Quality, Warnungen), `schemaVersion`, `metadata.coverage` (welche Analyseteile enthalten sind); nur normalisierte Felder, keine ARM-Rohdaten. Graph kompakt: Hierarchie über `parentId` (ohne `contains`-Kanten), Routen nur in `routes` (Routen-Kanten starten an der Route Table). |
| `azure-network-diff-YYYYMMDD-HHMM.json` | `drift/diff.ts` **[umgesetzt]** | Struktur nach § 78; `newFindings`/`resolvedFindings` = `null` bis Phase 11 |
| `.drawio` | `export/drawio` **[geplant]** | unkomprimiertes `mxfile`/`mxGraphModel`-XML; Positionen aus derselben ELK-Layout-Pipeline; Layer (`mxCell parent="0"`): Azure Architecture, IPv4, IPv6, Routing, Security, Assessment Findings; Kantenstile je Beziehungstyp; Azure-Shapes aus der eingebauten diagrams.net-Bibliothek (`img/lib/azure2/...`) |
| SVG **[geplant]** | CLI: aus Layout direkt; UI: aus React Flow | |
| PNG **[geplant]** | UI (`html-to-image`) | CLI-PNG nicht vorgesehen (keine Headless-Browser-Abhängigkeit) |
| CSV **[geplant]** | `export/csv` | Ressourcen-Inventar |

### 17.1 Sanitization

**[teilweise]** `src/export/sanitize.ts` (`sanitizeExport`), UI-Einstieg über den Button „KI-Analyse“ (§ 22). CLI-Flag `--sanitize`/`--sanitize-key` noch offen.

- Deterministische Pseudonyme via HMAC-SHA-256 mit einem vom Aufrufer übergebenen Schlüssel (kein Default, kein Speichern des Schlüssels). Gleicher Schlüssel ⇒ vergleichbare sanitisierte Exporte (Drift-Vergleich auf sanitisierten Daten bleibt möglich); anderer Schlüssel ⇒ andere Pseudonyme, nicht korrelierbar.
- Subscription-/Resource-Group-/Tenant-GUIDs → `guid-<hash8>` bzw. `sub-<hash8>`/`rg-<hash8>`; jedes Namenssegment einer ARM-Resource-ID → `res-<hash8>`. Wirkt sowohl auf einzelne ID-Felder als auch auf zusammengesetzte Strings (Graph-Kanten-IDs der Form `<typ>:<sourceId>-><targetId>#<qualifier>`) und auf freitextliche Felder (`name`, `reason`, `summary`, `firstHop`, …) über einen zweiten Whole-Word-Ersetzungsdurchlauf, damit derselbe Name nicht über ein Nebenfeld wieder auftaucht.
- Öffentliche IPv4/IPv6-Adressen → deterministische Abbildung in RFC-5737/RFC-3849-Dokumentationsbereiche (`198.51.x.x`, `2001:db8:...`); Familie bleibt erhalten. Private Adressen (RFC1918, ULA, Link-Local) bleiben **unverändert**, da sie für die IPv6-Leck-Analyse (z. B. „welches private Subnet hat trotzdem eine öffentliche Route“) strukturell relevant sind und keine Tenant-Identität preisgeben.
- Azure-Pflichtnamen (`GatewaySubnet`, `AzureFirewallSubnet`, `AzureFirewallManagementSubnet`, `AzureBastionSubnet`, `RouteServerSubnet`) bleiben als Literal erhalten – sie sind Plattformvorgaben, keine Tenant-Information.
- Felder, deren Schlüsselname nach Secret aussieht (`*key*`, `*secret*`, `*password*`, `*token*`, `*credential*`, `connectionString`, `sas`, `sharedKey`), werden unabhängig vom Wert durch `[REMOVED]` ersetzt – zusätzlich zur Secret-Blocklist der Normalisierung (zweite Verteidigungslinie).
- Struktur, Beziehungen (Graph-Kanten), Präfixlängen, Ports, Protokolle, NSG-/Routing-/Firewall-Entscheidungen und Zählwerte bleiben unverändert – notwendig, damit eine externe Analyse (Mensch oder KI, § 22) IPv6-Lecks und Architektur-Lücken weiterhin erkennen kann.
- Getestet (`tests/export/sanitize.test.ts`): Determinismus, Schlüsselwechsel ändert Pseudonyme, keine reale Subscription-/Resource-/Public-IP-Leckage (inkl. zusammengesetzter Graph-Kanten-IDs und Freitextfelder), Plattform-Subnetznamen bleiben erhalten, strukturelle Felder bleiben identisch.

---

## 18. UI-Architektur

**[teilweise]** Ist-Stand:

- **Stack**: React 19 (lokaler Komponenten-State, kein Store), Vite 8, `@xyflow/react` 12, `elkjs` 0.12, CSS-Custom-Properties als Theme-Tokens (`--network-*`, `--cat-*`, `--edge-*`, `--change-*`, Light/Dark über `prefers-color-scheme`).
- **Layout**: Drei Spalten – Tree View (links), Topologie mit Toolbar, Vergleichs- und Fokusleiste, Legende (Mitte), Detail-Panel bzw. Änderungsliste (rechts). Tabs „Topologie“ und „Übersicht & Qualität“.
- **Levels of Detail 1–5**: Knoten tragen `lod`; sichtbar ist `lod ≤ Stufe` plus Kinder aufgeklappter Knoten (Doppelklick). Knoten mit sichtbaren Kindern werden zu Containern (Subscription → Region → VNet → Subnet). Beziehungen zu verborgenen Knoten werden zum nächsten sichtbaren Vorfahren hochgezogen und zusammengefasst („×n“). Grenze 1.500 sichtbare Elemente (Hinweis statt Graph).
- **Fokus**: Teilbaum eines Elements plus direkt verbundene Elemente (maximal auf Ressourcenebene, Routen/Regeln werden zu Tabelle/Policy zusammengefasst).
- **Layout**: ELK je Container getrennt (`SEPARATE_CHILDREN`): `layered` mit Coffman-Graham-Ebenenbegrenzung bei verbundenen Kindern, sonst `rectpacking`; Querbeziehungen werden auf der Ebene des kleinsten gemeinsamen Containers berücksichtigt. ELK läuft über `elk-api` im Hauptthread mit **ELKs eigenem** `elk-worker.min.js` als klassischem Web Worker (eingebunden per Vite `?url`). Ein eigener Worker mit `elk.bundled.js` funktioniert nicht, weil ELK sich in einer Worker-Umgebung selbst als Dispatcher registriert. Layout-Cache pro Struktur, 60-s-Timeout.
- **Filter** (`src/graph/view.ts`): **IP-Modi** `Alle | IPv4 | IPv6 | Dual Stack` und **„Nur Änderungen“** (bei aktivem Vergleich) wirken gemeinsam: passende Komponenten normal, direkt verbundene und umschließende Komponenten als Kontext (blass, gestrichelt), übrige ausgeblendet; Kanten ohne passendes Ende als Hintergrund. Subscription-Filter.
- **Tree ↔ Graph**: gemeinsame Auswahl; Auswahl im Baum, in der Suche oder in Links klappt die Vorfahren im Graphen auf und zentriert das Element.
- **Suche**: Name, Resource ID, Resource Group, IP und CIDR (Containment: Adresse → NIC/VM, Subnet, VNet) im Hauptthread.
- **Snapshot-Vergleich**: siehe [SNAPSHOT-AND-DRIFT.md](SNAPSHOT-AND-DRIFT.md).

**[geplant]**: Dashboard-Kennzahlen (§ 58), weitere Filter (Region, Resource Group, Typ, Hub/Spoke, Severity), virtualisierter Baum, Such-Worker/IP-Index, IP-Modus **Compare** mit Pfad-Split (Phase 9), Path-Trace-, Findings- und Dual-Stack-Ansichten.

### 18.1 Anmeldung & Datenzugriff in der UI

Statische SPA ohne Backend. Ohne Anmeldung sind Import und Offline-Analyse verfügbar. Nach Anmeldung (MSAL-Popup, Redirect-Bridge) läuft die Discovery im Browser mit Fortschrittsanzeige über alle erreichbaren Tenants; Normalisierung und Graph (≈ 40 ms) laufen im Hauptthread. Der Discovery-Cache liegt nur im Arbeitsspeicher des Tabs (nur Ressourcendaten, keine Tokens) und wird beim Abmelden verworfen.

---

## 19. CLI

**[teilweise]** Umgesetzt:

```bash
npm run discover -- [--credential default|cli|vscode|mi|workload] [--tenant <id>]... [--subscription <id>]... \
                    [--out output/] [--no-cache] [--no-management-groups] [--log-level debug|info|warn|error]
npm run verify:arg -- [--credential cli] [--tenant <id>]    # ARG-Abdeckung (nur Aggregate)
npm run dev | npm run build && npm run preview               # Web-UI (MSAL-Anmeldung)
```

Ausgabe von `discover`: `output/raw-inventory.json` (Rohdaten, nur lokal/Debug), `output/network-assessment.json` und `output/azure-network-assessment-YYYYMMDD-HHMM.json` (normalisierter Export = Snapshot). Logs als JSON Lines auf stderr. Exit-Codes: 0 vollständig, 2 abgeschlossen, aber unvollständig (Warnungen ohne Hinweise oder Konfidenz ≠ HIGH), 1 Fehler.

**[geplant]**: `assess`, `export --format json|drawio|svg|csv [--sanitize]`, `snapshot`, `diff --from --to [--baseline]`.

---

## 20. Logging

**[teilweise]** Strukturiert (JSON Lines, `src/logging/logger.ts`), Level `debug|info|warn|error`; jeder Log-Eintrag läuft vor dem Schreiben durch `redact()` (entfernt Werte, deren Schlüssel nach `authorization|token|secret|password|key|sas|signature|cookie|credential` aussieht, sowie Bearer-Token/JWT-Muster im Wert – unabhängig vom Feldnamen).

**Tatsächlich erzeugte Events** (Stand 2026-09-26, per Code-Grep verifiziert):

| Event | Wo | Inhalt |
| --- | --- | --- |
| `discovery.start` / `discovery.complete` | `src/discovery/runDiscovery.ts` | Start/Ende der Discovery, `resources`, `warnings`, Quality-Zahlen |
| `tenants.discovered` / `subscriptions.discovered` | `src/discovery/runDiscovery.ts` | Anzahl erreichbarer Tenants/Subscriptions |
| `arg.query` | `src/azure/resourceGraph/runQuery.ts` | Pro ARG-Query: Dauer, Zeilenzahl, Truncation |
| `arg.page` (debug) | `src/azure/resourceGraph/runQuery.ts` | Pro Seite (nur bei `debug`-Level sichtbar) |
| `arg.page.reduce` | `src/azure/resourceGraph/runQuery.ts` | Adaptive Seitengrößen-Reduktion nach 413/Truncation |
| `arg.unexpectedFormat` / `arg.invalidRow` | `src/azure/resourceGraph/runQuery.ts` | Zod-Validierungsfehler einzelner ARG-Zeilen |
| `arm.enrichment` | `src/azure/arm/enrichment.ts` | Ergebnis der ARM-Enrichment-Phase je Tenant |

**Noch nicht implementiert** (in einer früheren Fassung dieses Dokuments fälschlich als vorhanden aufgeführt): `normalization`, `graph.build`, `routing.analysis`, `dualstack.analysis`, `assessment`, `snapshot`, `export` – diese Pipeline-Schritte laufen synchron im Hauptthread der UI bzw. der CLI ohne eigenen Log-Event; sie sind über die Dauer der jeweiligen Phase (`discovery.complete` bzw. CLI-Exit-Code) nur indirekt nachvollziehbar. Nachzuholen mit Phase 11 (Assessment Engine) und Phase 12 (Snapshots), sobald diese Phasen eigene, klar abgrenzbare Schritte sind.

Felder je Eintrag: `ts`, `level`, `event`, plus event-spezifische Zahlen (`durationMs`, `resources`, `pageSize`, …); nirgends `scope`/Subscription-IDs als eigenes Standardfeld – falls eine Subscription-ID geloggt werden soll, muss sie explizit in den `fields`-Parameter des jeweiligen `logger.info(...)`-Aufrufs aufgenommen werden (Redaction greift nur bei Schlüssel-/Wert-Mustern, nicht bei Feldnamen wie `subscriptionId`, die also **nicht automatisch versteckt** werden – bewusst, da Subscription-IDs kein Geheimnis sind, aber bei einer Weitergabe des Logs an Dritte zu bedenken).

**CLI-Sink**: JSON Lines auf `stderr` (§ 19). **UI-Sink**: `consoleSink()` in die Browser-Devtools; es gibt keinen persistenten/serverseitigen Log-Speicher – jede Sitzung ist isoliert, nichts verlässt den Browser über die Konsole hinaus.

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
| R14 | Definition of Done verlangt reale Azure-Tests. | CI kann das nicht leisten. | Automatisierte Tests mit Fixtures; manuelle Abnahme-Checkliste gegen realen Tenant (`docs/ACCEPTANCE.md`), plus optionaler `npm run test:live` (read-only, nur aggregierte Assertions). |
| R15 | SPA-Refresh-Tokens gelten nur 24 h; Third-Party-Cookie-Blocking verhindert Silent Renew im iframe. | Erneute Anmeldung während langer Sitzungen. | `acquireTokenSilent` → bei `InteractionRequiredAuthError` Popup; Discovery ist wiederaufnehmbar (Cache). |
| R16 | MSAL v5 erfordert eine Redirect-Bridge-Seite; falsche Redirect-URI führt zu `no_token_request_cache_error`. | Anmeldung scheitert. | **Eingetreten und behoben:** `redirect.html` als eigene Seite, Redirect-URI `<origin>/redirect.html`, dokumentiert in ENTRA-ID-SETUP. |
| R17 | ELK in einem eigenen Web Worker beantwortet Anfragen nicht (registriert sich selbst als Dispatcher). | Layout hängt endlos. | **Eingetreten und behoben:** `elk-api` + `elk-worker.min.js`; Regressionstest simuliert den Worker-Scope; 60-s-Timeout. |
| R18 | Größe des Exports (realer Tenant ~9 MB) für KI-Uploads. | Kontextgrenzen von KI-Werkzeugen. | Graph bereits kompakt (ohne `contains`-Kanten und Routen-Knoten); geplant: kompakte KI-Variante ohne Detailtabellen (Phase 14). |
| R19 | Build-Größe des UI-Bundles (~900 kB, ELK-Worker 1,6 MB). | Ladezeit beim ersten Aufruf. | Code-Splitting (Lazy-Load der Topologie) in Phase 7-Restpunkten. |
| R20 | Azure-OpenAI-API-Key liegt im gebauten Browser-Bundle (`VITE_AZURE_OPENAI_API_KEY`), da die SPA keinen Server hat. | Wer das Bundle einsehen kann (z. B. Browser-DevTools), sieht den Key. | Nur ein kostenlimitiertes, isoliertes Azure-OpenAI-Deployment verwenden (nicht denselben Key wie produktive Workloads); Key regelmäßig rotieren; Feature ist optional (§ 22) und standardmäßig ohne Konfiguration inaktiv; **nicht** für produktiven Mehrbenutzerbetrieb ohne eigenes Backend/Proxy geeignet. |
| R21 | Der KI-Provider (Azure OpenAI) sieht den sanitisierten Export, auch wenn reale Namen/IDs/Public-IPs pseudonymisiert sind. | Restrisiko: Traffic-Muster, Ressourcenzahl, Regionen, offene Ports könnten in seltenen Fällen eine Re-Identifikation über Kontextwissen erlauben (kein rein technisches Datenschutzproblem). | Nutzung ist ausdrücklich optional (Button, keine automatische Übertragung); Empfehlung: bei hoher Sensibilität nur mit einem privaten/dedizierten Azure-OpenAI-Deployment ohne Data-Retention-Zustimmung für Trainingszwecke arbeiten (Azure OpenAI verarbeitet Kundendaten laut Microsoft standardmäßig nicht für Modelltraining, siehe Microsoft-Datenschutzdokumentation). |
| R22 | Der Sanitizer-Schlüssel wird zur Bequemlichkeit in `localStorage` gemerkt (§ 22.1) statt bei jeder Sitzung neu eingegeben zu werden müssen. | Wer physischen/Skript-Zugriff auf den Browser-Profilspeicher hat, kann denselben Schlüssel für weitere sanitisierte Exporte wiederverwenden (Korrelation über mehrere Sitzungen hinweg – der Schlüssel selbst ist aber kein Azure-Geheimnis und ohne den zugehörigen realen Export wertlos). | Feld ist `type="password"`, nichts wird geloggt; Nutzer, die dieses Risiko nicht eingehen wollen, können den Browser im privaten Modus verwenden oder den Schlüssel nach der Sitzung manuell aus den Website-Daten löschen. |
| R23 | Eine „minimierte“ (fortsetzbare) Sitzung lässt ihren Azure-OpenAI-Vector-Store absichtlich am Leben, bis der Nutzer sie explizit beendet. | Vergisst der Nutzer, eine minimierte Sitzung zu beenden, laufen `file_search`-Speicher-/Indizierungskosten unbegrenzt weiter. | Sitzungsverzeichnis kennzeichnet fortsetzbare Sitzungen deutlich und weist auf die laufenden Kosten hin; der Nutzer muss eine Sitzung aktiv beenden (nicht nur schließen), um sie zu stoppen. |

---

## 22. KI-Analyse (Azure OpenAI)

**[umgesetzt]** `src/ai/azureOpenAi.ts` (HTTP-Client inkl. Datei-/Vector-Store-Endpunkte und Bild-Input), `src/ai/analyze.ts` (Chat-Session auf `file_search`-Basis + Report), `src/export/aiReportPdf.ts` (PDF-Rendering), `src/ui/workspace/FloatingOverlay.tsx` (verschieb-/größenveränderbares Fenster), `src/ui/workspace/aiSessionDirectory.ts` (lokales Sitzungsverzeichnis), UI-Panel `src/ui/workspace/AiAnalysisPanel.tsx` (Chat-Fenster mit Ladeanzeigen, Bildanhängen, Sitzungsverzeichnis), Button „KI-Analyse“ in `App.tsx`.

**Historie:** Ein erster Ansatz schickte den kompletten sanitisierten Export in einem Aufruf (überschritt das Token-Rate-Limit, `HTTP 429 rate_limit_exceeded`, real mit `gpt-5-mini`/`germanywestcentral`). Ein zweiter teilte ihn in viele Einzelaufrufe (ein Aufruf je VNet: bei ~80 VNets spürbar langsam) oder chattete direkt über den vollen Export als erste Nachricht (überschritt das Limit weiterhin, da der komplette Export weiterhin in einem Request steckte). Die aktuelle Lösung: **eine Chat-Session, deren Kontext über `file_search` gegen einen temporären Vector Store aufgelöst wird** – der Export zählt dadurch nicht in voller Länge gegen das Token-Budget jedes einzelnen Aufrufs, weil das Modell pro Anfrage nur die relevanten Ausschnitte abruft.

### 22.1 Ablauf

1. Nutzer klickt „KI-Analyse“ (nur aktiv, wenn ein Modell geladen ist) und gibt einen **Sanitizer-Schlüssel** ein (frei wählbar; wird zur Bequemlichkeit in `localStorage` gemerkt – Schlüssel `ai-sanitizer-key` – und beim nächsten Öffnen vorausgefüllt, damit er nicht bei jeder Sitzung neu eingegeben werden muss). Der Schlüssel ist kein Azure-Geheimnis, sondern ein selbst gewählter Wert, der nur lokal die Pseudonymisierung deterministisch macht (§ 17.1); er wird nie an Azure OpenAI oder sonst irgendwohin gesendet, nicht geloggt.
2. **Sitzung starten** (`startAnalysisSession`, mit sichtbarem Fortschritt je Phase):
   - *Anonymisieren*: `buildAssessmentExport()` + `sanitizeExport()` (§ 17.1). **Ab hier verlässt keine reale Tenant-Kennung mehr den Browser.**
   - *Hochladen*: `uploadFileSearchDocument()` formatiert den (an sich einzeiligen) `JSON.stringify`-Export vor dem Upload auf mehrzeiliges, eingerücktes JSON um – eine sehr lange einzelne Zeile ist für Azures Text-Extraktions-Pipeline anfälliger für Parserfehler als dieselbe Datei mehrzeilig – und lädt sie als Datei hoch (`POST /openai/v1/files`, `purpose=assistants`, MIME `text/plain`). Danach wird ein **temporärer** Vector Store angelegt (`POST /openai/v1/vector_stores`).
   - *Indizieren*: Die Datei wird an den Vector Store angehängt (`POST /openai/v1/vector_stores/{id}/files`) und der Ingestion-Status gepollt (`GET .../files/{id}`, Standard alle 1 s, Timeout 60 s). Schlägt die Verarbeitung mit `last_error.code = "server_error"` fehl (Azures generischer, in der Praxis meist transienter Fehler „An internal error occurred“), wird die Datei bis zu zweimal erneut angehängt und die Ingestion neu abgewartet, bevor der Fehler nach oben gereicht wird (`maxIngestAttempts`, Standard 3 Versuche insgesamt). Danach folgt ein erster kleiner Chat-Aufruf mit aktiviertem `file_search`-Tool (`tools: [{type: "file_search", vector_store_ids: [...]}]`), der die Sitzung eröffnet.
3. **Chatten** (`sendChatMessage`): Jede Nutzerfrage hängt über `previous_response_id` an die Sitzung an und behält `file_search` aktiviert – das Modell durchsucht bei Bedarf gezielt den Export, statt ihn erneut im Volltext zu erhalten. Kurze, günstige Folgeaufrufe unabhängig von der Tenant-Größe.
4. **Report erzeugen** (`generateReport`): Ein Aufruf mit `file_search` **und** Structured Outputs (`text.format = {type: "json_schema", strict: true}`, Schema `network_audit_report`: `summary`, `findings[]`, `recommendations[]`) fasst eine gezielte Suche nach IPv6-Lecks/Architektur-Gaps plus den bisherigen Chat zusammen. `generateReport()` bekommt so ohne Freitext-Heuristiken ein typisiertes `AiReport`-Objekt zurück.
5. `AiReport` wird clientseitig zu **PDF** gerendert (`aiReportPdf.ts`, `pdf-lib`, keine Serverkomponente) und ist zusätzlich als JSON herunterladbar.
6. **Sitzungsende**: Schließen des Panels (oder Unmount) löscht Datei und Vector Store (`endSession` → `deleteFileSearchDocument`, best effort, `finally`/Cleanup-Effekt) – der temporäre Speicher bleibt nie länger bestehen als die Sitzung.
7. Bei `HTTP 429` oder `5xx` wiederholt jeder Aufruf (inkl. Upload/Vector-Store-Erstellung/Polling) automatisch mit exponentiellem Backoff (Basis 2 s, Obergrenze 30 s, plus Jitter) bzw. respektiert einen vom Server gesendeten `Retry-After`-Header (Standard 4 Wiederholungen).

### 22.2 Ladeanzeige

Damit eine Wartezeit nachvollziehbar bleibt, zeigt die UI zwei gestaffelte Indikatoren:

- **Kurz** (Normalfall): ein rotierendes Netzwerk-Schild-Icon mit Klartext-Status (`sanitizing`/`uploading`/`indexing`/„Durchsuche den Export …“/„Erzeuge Report …“ bzw. bei einem Retry „Rate-Limit erreicht (HTTP 429) – warte X s, dann Versuch N …“).
- **Lang** (≥ 4 s, typischerweise ein Rate-Limit-Backoff): zusätzlich fünf Punkte in Regenbogenfarben, die von der Mitte nach außen abwechselnd hoch und runter „hüpfen“ (`ai-rainbow-dots`) – ein zweites, auffälligeres Signal, dass die Anwendung weiterarbeitet statt hängengeblieben zu sein.

### 22.3 Warum das schneller/günstiger ist als die vorherigen Ansätze

- Kein Request trägt mehr den kompletten Export im Prompt – `file_search` löst pro Anfrage nur die relevanten Chunks auf, wodurch die Tenant-Größe nicht mehr direkt das Token-Budget jedes einzelnen Aufrufs bestimmt.
- Der Export wird **genau einmal** hochgeladen (Sitzungsstart), nicht einmal pro VNet und nicht komplett in jeder Chat-Nachricht. Folgefragen sind kurze Texte.
- Eine zusätzlich identifizierte Ursache für lange Wartezeiten lag nicht im Modellaufruf, sondern im **Sanitizer**: `sanitizeExport()` importierte den HMAC-Schlüssel früher pro pseudonymisiertem String neu über `crypto.subtle.importKey` (mehrere tausend Aufrufe bei einem großen Export). Der Schlüssel wird jetzt **einmal pro Sanitize-Lauf** importiert und wiederverwendet (`Pseudonymizer.create()`), das Ergebnis ist unverändert (siehe `tests/export/sanitize.test.ts`).

### 22.4 Fenster, Bildanhänge, Sitzungsverzeichnis

- **Fenster** (`src/ui/workspace/FloatingOverlay.tsx`): Das Panel ist kein fester Seitenbereich mehr, sondern ein frei positionierbares Overlay – Titelleiste zum Verschieben (Pointer-Events, kein natives Drag'n'Drop), drei Resize-Griffe (rechts, unten, Ecke unten rechts, Mindestgröße 340×320 px). Position und Größe werden in `localStorage` (`ai-overlay-rect`) gemerkt und beim nächsten Öffnen wiederhergestellt; bei einer Fenstergrößenänderung wird die Position in den sichtbaren Bereich zurückgeklemmt.
- **Bildanhänge**: Ein aus der Zwischenablage eingefügtes Bild (`onPaste` im Eingabefeld) wird als Base64-Data-URI gelesen und der **nächsten Chat-Nachricht** als `input_image`-Inhalt beigefügt (`callAzureOpenAi({images: [...]})` → `input` wird zu einem strukturierten `[{role: "user", content: [{type: "input_text", ...}, {type: "input_image", ...}]}]`-Array statt eines reinen Strings). Das Bild landet **nicht** im Vector Store – `file_search` indiziert nur textbasierte Dokumente (§ 22.2), ein Bild ist visueller Kontext für genau diesen einen Turn, kein durchsuchbares Dokument. Mehrere Bilder können vor dem Senden gesammelt und einzeln wieder entfernt werden.
- **Sitzungsverzeichnis & Minimieren/Fortsetzen** (`src/ui/workspace/aiSessionDirectory.ts`): Ein Eintrag ist entweder **`minimized`** (Fenster geschlossen, Azure-OpenAI-Datei/Vector-Store bleiben absichtlich am Leben, volle Sitzung inkl. Chatverlauf in `localStorage` gesichert – auch über einen Seiten-Reload hinweg fortsetzbar) oder **`ended`** (Nutzer hat die Sitzung explizit beendet, Datei/Vector-Store sind gelöscht, nur Metadaten bleiben als Historie zurück, nicht reaktivierbar). Der Fenster-Titelleiste-Button „Minimieren“ ruft `saveResumableSession()` auf (persistiert `doc`, `lastResponseId`, `messages`, `sanitizationStats` – **nie** den Azure-OpenAI-API-Key, der beim Fortsetzen frisch aus `VITE_AZURE_OPENAI_*` neu aufgebaut wird, siehe `resumeSession()` in `src/ai/analyze.ts`) und schließt das Fenster, ohne den temporären Speicher zu löschen; der X-Button in der Titelleiste beendet dagegen wie zuvor sofort (`endSession` + `recordSessionEnded`). Ein Klick auf einen fortsetzbaren Eintrag im Sitzungsverzeichnis ruft `resumeSession()` auf (keine Netzwerkaufrufe, reine Rekonstruktion) und lädt den kompletten Chatverlauf zurück in die UI. Da ein `minimized` Vector Store weiterhin `file_search`-Kosten verursacht, weist das Sitzungsverzeichnis explizit darauf hin.

### 22.5 Konfiguration

`.env.local` (siehe `.env.example`): `VITE_AZURE_OPENAI_ENDPOINT`, `VITE_AZURE_OPENAI_API_KEY`, `VITE_AZURE_OPENAI_MODEL`. Ohne diese drei Werte bleibt der Button inaktiv mit Hinweistext; es gibt keinen Fallback-Provider und keine automatische Aktivierung.

### 22.6 Grenzen

- Der API-Key liegt im Client-Bundle (R20) – siehe dortige Gegenmaßnahmen.
- Die Analyse ist eine Ergänzung, kein Ersatz für die deterministische Pfad-/Sicherheitsanalyse (§ 12–14): Modellantworten sind nicht reproduzierbar und tragen keine `Confidence`/`Evidence`-Struktur wie der Rest des Tools.
- Es findet keine automatische, wiederkehrende Analyse statt (kein Scheduler, kein Hintergrundjob) – jede Sitzung ist eine bewusste Nutzerinteraktion.
- `file_search` verursacht in Azure OpenAI zusätzliche Kosten (Speicherung/Indizierung des Vector Store) neben den Token-Kosten der Aufrufe selbst; die Sitzung hält den Vector Store deshalb bewusst nur so lange wie nötig und löscht ihn beim Schließen des Panels.
- `file_search` zerlegt das Dokument intern in Chunks für die Volltextsuche; ein Fund, der mehrere Felder (Subnet, NSG-Regel, Route) gemeinsam sehen muss, kann in seltenen Fällen auf mehrere Chunks verteilt werden. Die Instruktionen weisen das Modell explizit an, diese Felder zusammen zu prüfen, ersetzen aber keine Garantie.
- `pdf-lib` erhöht das Browser-Bundle um ~420 kB (gzip ~170 kB) – ein bewusster Kompromiss für reine Client-PDF-Erzeugung ohne Server (R19 bereits vorbestehend zur Bundle-Größe).
- Ein eingefügtes Bild wird **nicht** durch `sanitizeExport()` geprüft oder anonymisiert – anders als der Export selbst kann ein Screenshot reale Namen/IDs/IP-Adressen enthalten, wenn der Nutzer eines aus dem Azure Portal einfügt. Das liegt in der Verantwortung des Nutzers; sobald ein Bild an die nächste Nachricht angehängt ist, zeigt die UI eine deutliche Warnung, bevor gesendet wird.
- Das Sitzungsverzeichnis (`localStorage`) ist pro Browser/Gerät, nicht synchronisiert; ein anderes Gerät oder ein anderer Browser sieht keine frühere Historie.
