# IMPLEMENTATION PLAN — Azure Network Audit Assistant

Stand 2026-09-25 · Referenz: [ARCHITECTURE.md](ARCHITECTURE.md)

## 0. Arbeitsregeln

**Quality Gate nach jeder Phase** (Pflicht, keine nächste Phase vorher):

```
npm run typecheck   # tsc --noEmit, strict
npm run lint        # eslint (inkl. Schichtgrenzen, no-explicit-any, Read-only-Regeln)
npm run test        # vitest run
npm run build       # ab Phase 7 inkl. UI-Build
```

- Keine Regression: bestehende Tests bleiben grün; Coverage-Schwelle für `src/{addressing,routing,dualstack,assessment,snapshots,drift,export}` ≥ 85 % Lines.
- Keine Mocks außerhalb von `tests/`. Keine statischen Beispieldaten im Produktionspfad. Keine TODOs für Kernfunktionen.
- `any` nur mit `// eslint-disable-next-line @typescript-eslint/no-explicit-any -- <Begründung>`.
- Jede Phase endet mit einem Commit (Conventional Commits) und aktualisierter Doku des betroffenen Bereichs.

**Toolchain (gepinnt):** Node ≥ 22 (entwickelt mit 26), TypeScript 6.0.x, ESLint 10 + typescript-eslint 8, Prettier, Vitest 5, Vite 8, React 19, `@xyflow/react` 12, `elkjs` 0.12, Zod 4, commander 15, Zustand 5, `@azure/msal-browser` 5, Azure SDKs gemäß ARCHITECTURE § 1.1.

---

## Phase 1 — Repository-Analyse ✅
Ergebnis: Greenfield (nur `LICENSE`), Toolchain und SDK-Versionen verifiziert, ARG-Abdeckung live geprüft (ARCHITECTURE § 1).

## Phase 2 — Architektur ✅ (dieses Dokument + ARCHITECTURE.md)
Freigegeben am 2026-09-25 mit folgenden Entscheidungen: strikt read-only; BGP-Routen als `POSSIBLE`/`UNKNOWN`; **Web-UI-Anmeldung per MSAL** (Auth Code + PKCE, direkte ARM-Aufrufe aus dem Browser, kein lokaler Server); Doku auf Deutsch.

---

## Phase 3 — ARG-Query-Katalog ✅
**Deliverables**
- `RESOURCE-GRAPH-QUERIES.md`: jede Query (ID, Tabelle, KQL, projizierte Felder, erwartete Kardinalität, Paging-Hinweise, bekannte Lücken → Enrichment-ID).
- `AZURE-DISCOVERY.md`: Pipeline, Scopes, Batching, Throttling, Cache, Rechte.
- Verifikationsskript `scripts/verify-arg-coverage.ts` (read-only, nur `summarize`/`bag_keys`) — prüft pro Typ, welche Properties ARG liefert; Ergebnis fließt in die Doku (ohne Tenantdaten).
- Offene Punkte aus ARCHITECTURE § 1.2 klären: vWAN-Kinder, ER-Peerings, Front-Door-Kinder, Route-Server-BGP, AAAA in `dnsresources`, VMSS-NICs.

**Exit:** Jede Datenanforderung aus Lastenheft §§ 10–31 ist genau einer Query oder einem Enrichment zugeordnet (Traceability-Tabelle).

## Phase 4 — Projekt-Scaffold & ARG-Discovery ✅
Ergebnis 2026-09-25: Typecheck, Lint, 60 Tests und Build grün. Reale CLI-Discovery: 38/38 Subscriptions, 1.097 Netzwerkressourcen, 68 ARG-Abfragen ohne Fehler (~29 s). Die Browser-Anmeldung ist implementiert und getestet (Unit-Tests); der Live-Test braucht eine App-Registrierung ([ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md)).

**Deliverables**
- `package.json`, `tsconfig` (strict, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`), ESLint-Config inkl. `no-restricted-imports`-Schichtregeln, Prettier, Vitest-Config.
- `src/logging` (JSON Lines + Redaction).
- `src/auth/node` (DefaultAzureCredential-Factory, Tenant-Wrapper).
- `src/auth/browser`: MSAL-Konfiguration aus `VITE_ENTRA_*`, `MsalTokenCredential` (tenant-gebundene Authority, silent → Popup), Login/Logout, minimale Login-Oberfläche als Einstieg der UI; `ENTRA-ID-SETUP.md`.
- `src/azure/http`: `readOnlyGuardPolicy`, Retry/Backoff, Quota-Drossel, Concurrency-Limiter.
- `src/azure/subscriptions`, `src/azure/resourceGraph` (Katalog aus Phase 3, Paging, Batching, Split bei 403/Truncation, Cache).
- `src/discovery` → `RawInventory`, `DiscoveryQuality`, `warnings[]`.
- CLI `discover` (schreibt `output/raw-inventory.json`, nur für Debug; Default-Export kommt in Phase 14).

**Tests:** Guard-Policy (alle HTTP-Methoden, Allowlist), `MsalTokenCredential` (Scope, Authority pro Tenant, Silent/Interaction-Fallback, gemockte MSAL-Instanz), Paging (mehrseitig, Truncation), Batching/Split, Retry mit `Retry-After`, Fehlerisolation (ein Batch 403 → Rest ok, Warnung erzeugt), Redaction.
**Exit:** `npm run discover` läuft gegen einen realen Tenant (manuell), Discovery-Quality plausibel; Browser-Anmeldung per MSAL liefert ein ARM-Token, mit dem die Subscription-Liste im Browser abgerufen wird.

## Phase 5 — ARM-Enrichment
**Deliverables:** `src/azure/arm` mit Enrichment-Plan (aus RawInventory abgeleitet), Clients über `createReadOnlyClient`, Cache (`resourceId+etag`), `EnrichmentResult` in Discovery-Quality; Diagnostic-Settings-Abfrage für Kontrollpunkte; optional `--effective-routes`.
**Tests:** Plan-Ableitung (nur Lücken werden angereichert), 403 → `not-accessible` + Warnung, Cache-Hit, Concurrency-Grenze.

## Phase 6 — Normalisierung & Network Graph ✅
Ergebnis 2026-09-25: Normalisierung aller erfassten Typen, Graph (Hierarchie + 13 Beziehungstypen, externe/nicht lesbare Ziele als eigene Knoten), Hub/Spoke- und NVA-Heuristik. Realer Tenant: 1 Hub (Konfidenz 1.0), 55 Spokes, 18 Standalone, 4 unklar; 3.662 Knoten / 6.896 Beziehungen, Analyse in ~40 ms.

**Deliverables:** `src/models` (Zod-Schemas für alle Normalized-Typen, Graph, Evidence), `src/normalization` (ein Normalizer pro Typ, `addressPrefix`/`addressPrefixes`-Merge, lowercase-IDs, Secret-Blocklist), `unclassifiedNetworkResources[]`, `src/graph` (Nodes/Edges/Indizes, LOD-Zuordnung, Hierarchie), `src/topology` (Hub/Spoke/Shared/Standalone, NVA-Heuristik mit `confidence`/`reasons`).
**Tests:** Normalizer je Typ (Fixtures), VNet-Beziehungen, Peering-Erkennung (beidseitig/asymmetrisch/Disconnected, Subnet-Peering), Hub-Detection, Spoke-Detection, vWAN, NVA-Heuristik, unklassifizierte Typen bleiben erhalten, keine Secrets im Output.

## Phase 7 — Topology UI + Tree View ✅ (Kern) / offen: Tree-Virtualisierung, UI-Komponententests
Ergebnis 2026-09-25: React Flow + ELK im Web Worker (Layout ≤ 0,2 s bis 1.234 Elemente, Layout-Cache), Level of Detail 1–5, Drilldown per Doppelklick, Fokus mit Breadcrumb, Tree View synchronisiert, Detail-Panel mit Beziehungen und typspezifischen Tabellen (Peerings, Routen, NSG-/Firewall-Regeln, DNS-Records), globale Suche inkl. IP/CIDR-Containment, IP-Modi, Subscription-Filter, JSON-Export/Import (vorgezogen aus Phase 14, Abdeckung in `metadata.coverage`).

**Deliverables:** Vite/React-App (statische SPA) mit MSAL-Anmeldung (siehe Phase 4), Discovery im Browser, Zustand-Store, Topologie mit React Flow + ELK-Worker, Cluster (Subscription/Region), LOD 1–5, Expand/Collapse/Double-Click/Focus, Mini-Map, Zoom, Fit View, Breadcrumb, virtualisierter Tree View mit Graph-Sync, Detail Panel, Dashboard (Zählwerte + Discovery Quality + Warnings), Theme-Tokens Light/Dark, Snapshot-Import (offline) bereits hier als Datenquelle.
**Tests:** Store/Selektion-Sync, LOD-Filterung, Layout-Cache-Key, Komponenten-Smoke-Tests (Vitest + Testing Library), Performance-Test mit synthetischem Graph (≥ 2 000 Knoten, Layout im Worker < definierte Schwelle).

## Phase 8 — IPv4/IPv6-Addressing
**Deliverables:** `src/addressing` (bigint-CIDR, RFC-5952, Containment, Overlap, IP-Index/Intervallbaum, Adresskategorien ULA/GUA/NAT64/RFC1918/CGNAT), Klassifikation pro Knoten, Overlap-Erkennung (VNet-übergreifend, inkl. gepeerter VNets), globale Suche (Name/ID/IP/CIDR/Sub/RG/VNet/Subnet) im Worker, Filter (inkl. IPv4/IPv6/Dual-Stack/Hub/Spoke/Severity), UI-IP-Modi `IPv4 | IPv6 | Dual Stack | Compare`.
**Tests:** IPv4 CIDR, IPv6 CIDR (Kompression, Grenzen /0, /128), Subnet-Containment, Overlapping Networks, IP-Suche liefert VNet/Subnet/NIC/PIP/Prefix.

## Phase 9 — Routing Path Analyzer
**Deliverables:** `src/routing` (Effective-Route-Synthese pro Subnet × Familie, LPM mit UDR>BGP>System, Gateway-abgeleitete Routen, vWAN), Egress-Resolver (Priorität gemäß Doku, NAT-SKU-Fähigkeit je Familie), Path Tracer (Zustandsautomat, Zyklenerkennung, Hop-Evidence, Status ALLOWED/BLOCKED/UNKNOWN/POTENTIAL_BYPASS), `src/security` (NSG-Evaluator inkl. ASGs und Default Rules, Firewall-Policy-Modell mit Hierarchie, IP-Groups), UI „Trace Network Path" und „Compare IPv4/IPv6 Path".
**Verifikation vorab:** IPv6-Default-Outbound-Verhalten, Azure-Firewall-IPv6-Fähigkeiten, Gateway-IPv6 via Microsoft Learn → `capabilities`-Tabelle mit Quellen.
**Tests:** IPv4 Default Route, IPv6 Default Route, Firewall Path (UDR→FW→FW-Subnet-Route→Internet), NAT Path (inkl. Standard-SKU ohne IPv6), Peering-Nichttransitivität, Route `None`, ECMP, Forced Tunneling, NSG-Block, Zyklus.

## Phase 10 — Dual-Stack Gap Analysis
**Deliverables:** `src/dualstack` (Matrix pro VNet/Subnet mit Evidence, Gap-Erkennung aller Gap-Typen, Readiness pro Kategorie ohne Gesamtscore), UI-Matrix-Ansicht + Readiness-Karten, Kennzeichnung „Dual Stack with Gap".
**Tests:** Dual-Stack-Vergleich je Zeile, Gap nur bei existierender Zweitfamilie, `UNKNOWN` bei fehlenden Daten statt `READY`.

## Phase 11 — Assessment Engine
**Deliverables:** `src/assessment` (Rule-Interface, Engine, stabile Finding-IDs, Severity-Kontext, Confidence-Degradierung), Regelkatalog (mind. alle Regeln aus Lastenheft §§ 51, 56), `architectureGaps[]`, `assessmentContext`, `ASSESSMENT-RULES.md`, `IPV6-ASSESSMENT.md`, UI Findings-Liste + Findings im Detail Panel + Layer im Graph.
**Tests:** Pro Regel positiv/negativ/unbekannt; **Akzeptanztests 1 und 2**.

## Phase 12 — Architecture Snapshots
**Deliverables:** `src/snapshots` (Snapshot-Builder, kanonische Serialisierung, `configurationHash`/`tagsHash`/`findingsHash`, Zod-Import mit Schema-Migration), Baseline-Datei, CLI `snapshot`, UI Import.
**Tests:** Hash-Determinismus (Reihenfolge-Permutationen, volatile Felder ändern Hash nicht, fachliche Änderungen schon), Roundtrip Export→Import→identischer Hash.

## Phase 13 — Semantic Diff / Drift ◐ (vorgezogen, Kern umgesetzt)
Stand 2026-09-25: `src/drift/diff.ts` – semantischer Vergleich Snapshot → aktueller Stand (Ressourcen per ID, Feld-Diff auf dem normalisierten Modell, schlüsselbasierte Listen wie NSG-Regeln/Routen je Element), Drift-Kategorien, IPv4/IPv6-Bezug, Beziehungsänderungen, Diff-Export `azure-network-diff-*.json`. UI: „Mit JSON vergleichen“, NEU/GEÄNDERT/ENTFERNT-Markierungen in Graph und Baum, Geister-Knoten für Entferntes, Δ-Zähler an Containern, Filter „Nur Änderungen“, Änderungsliste, Vorher/Nachher im Detail-Panel. Offen: Finding-Lifecycle (nach Phase 11), Baseline-Markierung, Timeline, CLI `diff`.

**Deliverables:** `src/drift` (Resource-Matching, typ-spezifische Differ, abgeleitete Pfad-Änderungen, Drift-Kategorien, Security-Drift-Highlights, Finding-Lifecycle, Timeline, Baseline-Vergleich), CLI `diff`, UI Drift-Ansicht + Timeline, `SNAPSHOT-AND-DRIFT.md`.
**Tests:** **Akzeptanztests 3–7**, Tag-Änderung = INFORMATIONAL, Subnet+ = ARCHITECTURE_RELEVANT, Default-Route-Next-Hop = POTENTIALLY_BREAKING.

## Phase 14 — JSON Assessment Export
**Deliverables:** `src/export/json` (Struktur Lastenheft § 60 + `warnings`, `discoveryQuality`), Diff-Export (§ 78), Dateinamensschema, CSV-Inventar, JSON-Schema-Datei (aus Zod generiert) für KI-/Tool-Konsumenten, `NETWORK-GRAPH-MODEL.md`.
**Tests:** Schema-Validität, Pflichtsektionen, keine Rohdaten/Secrets, Dateiname.

## Phase 15 — Draw.io Export
**Deliverables:** `src/export/drawio` (mxfile-XML, Layer, Kantenstile je Beziehungstyp, Azure-Shapes, Positionen aus ELK in Node), SVG-Export (CLI aus Layout, UI aus React Flow), PNG (UI).
**Tests:** XML wohlgeformt, alle Layer vorhanden, jede Graph-Kante erscheint mit korrektem Stil, IDs eindeutig; Golden-File-Test; manuelle Prüfung in diagrams.net.

## Phase 16 — Sanitization & Security
**Deliverables:** `src/export/sanitize` (HMAC-Pseudonyme, präfixerhaltende Public-IP-Abbildung, ID-Umschreibung, Secret-Blocklist), `SECURITY.md` (Threat Model: MSAL-Tokens im Browser, CSP, Exporte, Read-only-Garantie).
**Tests:** Beziehungen/Containment/Präfixlängen nach Sanitization erhalten, Routing-/Assessment-Ergebnisse auf sanitisiertem Snapshot identisch (bis auf Namen), keine Originalwerte im Output (Leak-Scan), gleicher Key ⇒ gleiche Pseudonyme.

## Phase 17 — Tests (Konsolidierung)
**Deliverables:** Integrationstests über die komplette Pipeline mit Szenario-Fixtures (Hub/Spoke IPv4-only, Dual-Stack sauber, Dual-Stack mit Bypass, vWAN, NVA-HA), Akzeptanztests 1–7 als eigene Suite `tests/acceptance`, optionaler `npm run test:live` (read-only, nur Aggregat-Assertions), Coverage-Report.

## Phase 18 — Dokumentation
**Deliverables:** `README.md` (Installation, Node-Version, Login, RBAC, Start, Build, Discovery, Assessment, Exporte, Snapshot Import/Compare), Finalisierung von ARCHITECTURE, AZURE-DISCOVERY, RESOURCE-GRAPH-QUERIES, NETWORK-GRAPH-MODEL, IPV6-ASSESSMENT, ASSESSMENT-RULES, SNAPSHOT-AND-DRIFT, SECURITY; `docs/ACCEPTANCE.md` (manuelle Abnahme-Checkliste gegen realen Tenant entlang der Definition of Done).

---

## Akzeptanztest-Zuordnung

| Test | Szenario | Phase | Erwartung |
| --- | --- | --- | --- |
| 1 | IPv4 `0.0.0.0/0→FW`, IPv6 `::/0→Internet` | 11 | NET-IPV6-003 HIGH/CRITICAL „IPv6 bypasses centralized firewall" |
| 2 | IPv4 zentrales NAT, IPv6 Public IP an VM | 11 | NET-NAT-001 + `SECURITY_GAP`/`EGRESS_GAP` |
| 3 | A IPv4-only, B IPv6-VNet-Präfix | 13 | ADDED IPv6 Address Space, ARCHITECTURE_RELEVANT |
| 4 | A IPv6 ohne `::/0`-UDR, B `::/0→FW` | 13 | Finding RESOLVED, „Architecture Improvement" |
| 5 | A NSG blockt IPv6-Internet, B allow `::/0` inbound | 13 | NEW Finding NET-NSG-001 HIGH/CRITICAL, SECURITY_RELEVANT |
| 6 | A IPv4+IPv6 via Firewall, B IPv6-UDR entfernt | 13 | NEW EGRESS/FIREWALL-Bypass-Finding, POTENTIALLY_BREAKING |
| 7 | Finding in A, nicht in B | 13 | RESOLVED FINDING |

## Traceability Lastenheft → Phase (Kurzform)

| Lastenheft § | Phase |
| --- | --- |
| 4–6 Read-only, Auth, RBAC | 4, 16 |
| 7–8 Discovery-Pipeline | 3–5 |
| 10–31 Ressourcen | 3–6 |
| 32–35 Modell, Klassifikation, Hub/Spoke | 6, 8 |
| 36–44 UI, Suche, Filter | 7, 8 |
| 45–46 Path Trace | 9 |
| 47–54 Dual-Stack | 10 |
| 55–57 Assessment | 11 |
| 58 Dashboard | 7, 11 |
| 59–63 JSON/KI/Sanitize | 14, 16 |
| 64–67 Draw.io/SVG/PNG/CSV | 14, 15 |
| 68–78 Snapshot/Drift/Diff | 12, 13 |
| 79–81 UX/Performance | 7 |
| 82 CLI | 4, 12–15 |
| 83 Logging | 4 |
| 84–85 Tests | alle, 17 |
| 86–87 Doku | 3, 11, 13, 14, 16, 18 |
| 89–91 Fehler/Confidence/Quality | 4, 5, 11 |
