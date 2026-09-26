# IMPLEMENTATION PLAN — Azure Network Audit Assistant

Stand 2026-09-26 (Sanitizer + KI-Analyse vorgezogen aus Phase 16) · Referenz: [ARCHITECTURE.md](ARCHITECTURE.md)

## 0. Statusübersicht

Legende: ✅ fertig · ◐ teilweise (Kern umgesetzt, Restpunkte offen) · ○ offen

| Phase | Thema | Status | Kurzstand |
| --- | --- | --- | --- |
| 1 | Repository-Analyse | ✅ | Greenfield, Toolchain und SDKs verifiziert |
| 2 | Architektur | ✅ | freigegeben; Entscheidungen siehe Phase 2 |
| 3 | ARG-Query-Katalog | ✅ | 35 Queries, Traceability, Verifikationsskript |
| 4 | Scaffold & ARG-Discovery | ✅ | CLI + Browser-Discovery, Read-only-Guard, MSAL |
| 5 | ARM-Enrichment | ◐ | vWAN-Hub-Details (Connections, Routing Intent, Hub Route Tables) und Service-Tag-Präfixe fertig; Front Door, Diagnostic Settings, ER-Circuits, Cache/etag offen |
| 6 | Normalisierung & Graph | ◐ | Kern fertig; Evidence-/AccessStatus-Modell und einige Tests offen |
| 7 | Topologie-UI & Tree View | ◐ | Kern fertig; Dashboard-Kennzahlen, Filter, Virtualisierung, UI-Tests offen |
| 8 | IPv4/IPv6-Addressing | ◐ | CIDR/Containment, IP-Suche, IP-Modi, IPv4/IPv6-Pfadvergleich fertig; Overlap, RFC 5952, IP-Index offen |
| 9 | Routing Path Analyzer | ◐ | Ausgehend + eingehend (Internet → Workload), vWAN, AVNM, ECMP, Service Tags fertig; Effective-Routes-API, Ost-West-Übersicht, UI-Tests offen |
| 10 | Dual-Stack-Gap-Analyse | ○ | nicht begonnen |
| 11 | Assessment Engine | ○ | nicht begonnen |
| 12 | Architecture Snapshots | ◐ | Export = Snapshot, Import mit Validierung; `configurationHash`, Migration, Baseline offen |
| 13 | Semantic Diff / Drift | ◐ | Diff, Kategorien, UI-Markierungen, Diff-Export fertig; Finding-Lifecycle, Pfad-Drift, Timeline, CLI offen |
| 14 | JSON-Assessment-Export | ◐ | Export inkl. Default-Pfaden je Familie und IPv6-Bypass-Gaps; Dual-Stack-/Findings-Sektionen, CSV, JSON-Schema offen |
| 15 | Draw.io-Export | ○ | nicht begonnen |
| 16 | Sanitization & Security | ◐ | Sanitizer (`sanitizeExport`) fertig und getestet, per UI aufrufbar; CLI-Flag und `SECURITY.md` offen |
| 17 | Tests (Konsolidierung) | ◐ | 209 Tests; Coverage-Messung, Akzeptanzsuite, `test:live` offen |
| 18 | Dokumentation | ◐ | 8 von 10 Dokumenten vorhanden; `IPV6-ASSESSMENT.md`, `ASSESSMENT-RULES.md`, `SECURITY.md`, `docs/ACCEPTANCE.md` offen |
| 22 | KI-Analyse (Azure OpenAI) | ◐ | Sanitisierter Export → Azure OpenAI → Findings + Implementierungsplan-Vorschlag, per UI-Button; CLI-Äquivalent und Persistenz offen |

**Abweichung von der Reihenfolge:** Auf Wunsch des Auftraggebers wurden Ansicht/Drilldown (Phase 7), JSON-Export/-Import (Teile 12/14) und der Snapshot-Vergleich (Kern 13) vor Phase 5 und 8–11 umgesetzt. Die dort vorgesehenen Analyse-Ergebnisse (Routing, Dual-Stack, Findings) fließen nachträglich in Export und Vergleich ein; der Export kennzeichnet fehlende Teile in `metadata.coverage`.

### Empfohlene nächste Schritte

1. **Phase 10** Dual-Stack-Gap-Analyse und **Phase 11** Assessment Engine – bauen direkt auf den Pfadergebnissen auf; danach Akzeptanztests 1, 2, 4 (Finding-Sicht) und 7 sowie Finding-Lifecycle im Diff.
2. Rest **Phase 5** (Front Door, Diagnostic Settings, ExpressRoute-Circuits, Cache) – schließt Monitoring-Gaps.
3. Rest Phase 9: optionale Effective-Routes-API (`--effective-routes`) zur Bestätigung der synthetisierten Routen; Exposure-Findings in Phase 11 übernehmen.
4. **Phase 12** `configurationHash` + Baseline, danach 15 (Draw.io).
5. Rest **Phase 16**: CLI-Flag `--sanitize`/`--sanitize-key`, `SECURITY.md` (Threat Model inkl. R20/R21 aus ARCHITECTURE.md).
6. Rest **Phase 22**: Persistenz der KI-Analyseergebnisse im Snapshot/Export, CLI-Äquivalent zum UI-Button.

---

## 1. Arbeitsregeln

**Quality Gate nach jeder Phase** (Pflicht):

```text
npm run typecheck   # tsc --noEmit, strict
npm run lint        # eslint (inkl. Schichtgrenzen, no-explicit-any, Read-only-Regeln)
npm test            # vitest run
npm run build       # UI-Build (tsc + vite)
```

- Keine Regression: bestehende Tests bleiben grün. Zuletzt: 28 Testdateien, **187 Tests** grün, Build grün.
- **Coverage-Schwelle** ≥ 85 % Lines für `src/{addressing,routing,dualstack,assessment,snapshots,drift,export}`: *noch nicht messbar* – `@vitest/coverage-v8` wird in Phase 17 ergänzt.
- Keine Mocks außerhalb von `tests/`. Keine statischen Beispieldaten im Produktionspfad. Keine TODOs für Kernfunktionen.
- `any` nur mit `// eslint-disable-next-line @typescript-eslint/no-explicit-any -- <Begründung>` (derzeit keine Verwendung).
- **Commits** (Conventional Commits) erfolgen nach Freigabe durch den Auftraggeber. Stand: noch kein Commit über den Initial-Commit hinaus.
- Live-Prüfungen gegen den realen Tenant sind ausschließlich lesend; in die Dokumentation fließen nur aggregierte Zahlen, keine Tenantdaten.

**Toolchain (installiert, gepinnt):** Node ≥ 22 (entwickelt mit 26), TypeScript 6.0.3 (TS 7 wird von typescript-eslint noch nicht unterstützt), ESLint 10 + typescript-eslint 8, Prettier 3, Vitest 5, Vite 8, React 19, `@xyflow/react` 12, `elkjs` 0.12, Zod 4, commander 15, tsx, `@azure/msal-browser` 5, `@azure/identity` 4, `@azure/arm-resourcegraph` 5, `@azure/arm-resources-subscriptions` 3, `@azure/arm-network` 39 und `@azure/arm-cdn` 10 (beide für Phase 5 vorinstalliert).
Nicht verwendet (entgegen erster Planung): Zustand (React-State genügt), `@azure/msal-react` (eigene Session-Abstraktion), `@azure/arm-privatedns`/`arm-dnsresolver` (ARG deckt Records und Resolver ab).

---

## Phase 1 — Repository-Analyse ✅

Greenfield (nur `LICENSE`), Toolchain und SDK-Versionen verifiziert, ARG-Abdeckung live geprüft (ARCHITECTURE § 1).

## Phase 2 — Architektur ✅

Freigegeben am 2026-09-25 mit folgenden Entscheidungen: strikt read-only; BGP-Routen als `POSSIBLE`/`UNKNOWN`; **Web-UI-Anmeldung per MSAL** (Auth Code + PKCE, direkte ARM-Aufrufe aus dem Browser, kein lokaler Server); Doku auf Deutsch.

## Phase 3 — ARG-Query-Katalog ✅

- `RESOURCE-GRAPH-QUERIES.md` (Query-IDs, Tabellen, Inline-Daten, ARM-Lücken, Traceability zu Lastenheft §§ 10–31), `AZURE-DISCOVERY.md`.
- Offene Punkte geklärt: Management Groups, VMSS-NICs, Route-Server-BGP, AAAA-Records und AVNM liegen in ARG; vWAN-Kinder, Front-Door-Kinder und Diagnostic Settings brauchen ARM.
- `scripts/verify-arg-coverage.ts` (`npm run verify:arg`, nur Aggregat-Ausgabe).

## Phase 4 — Projekt-Scaffold & ARG-Discovery ✅

**Umgesetzt:** Projektkonfiguration (strict TS, ESLint-Schichtgrenzen und Read-only-Regeln), `src/logging` (JSON Lines + Redaction), `src/auth/node` (DefaultAzureCredential & Co.), `src/auth/browser` (MSAL, `MsalTokenCredential`, Redirect-Bridge `redirect.html` für MSAL v5), `src/azure/http` (`readOnlyGuardPolicy`, ARG-Quota-Drossel, SDK-Retry-Optionen), `src/azure/subscriptions`, `src/azure/resourceGraph` (Katalog, Paging, Batching, Split bei 403/Truncation, adaptive Seitengröße, Cache), `src/discovery` (RawInventory, DiscoveryQuality, Warnungen; optionale Daten wie Management Groups als Hinweise), CLI `discover`.
**Real verifiziert:** 38/38 Subscriptions, 1.097 Netzwerkressourcen, 68 ARG-Abfragen ohne Fehler (~29 s); Browser-Anmeldung und Discovery im Browser durch den Auftraggeber bestätigt (5/5 Tenants).
**Abweichung:** Retry/Backoff inkl. `Retry-After` übernimmt die SDK-Retry-Policy (konfiguriert, nicht separat getestet).

## Phase 5 — ARM-Enrichment ◐

**Umgesetzt:**
- `src/azure/arm/armReader.ts`: GET-only-Pipeline (Read-only-Guard, Retry, Bearer-Token je Tenant), folgt `nextLink`, konfigurierbarer Items-Key.
- `src/azure/arm/enrichment.ts`: je vWAN-Hub `hubVirtualNetworkConnections`, `routingIntent`, `hubRouteTables` (E-VWAN-01…03); Service-Tag-Discovery-API (E-SVC-01, Items-Key `values`), gefiltert auf tatsächlich referenzierte Tags. Fehler je Aufruf isoliert → `EnrichmentResult` + Warnung, `DiscoveryQuality.armEnrichment`.
- `runDiscovery` Phase „enrichment“ (Standard an), CLI `--no-enrichment`; Ergebnis in `RawInventory.enrichment`.

**Real verifiziert:** 3 referenzierte Service Tags aufgelöst; keine vWAN-Hubs im Tenant.
**Offen:** E-FW-01, E-ER-01, E-FD-01, E-MON-01, Cache (`resourceId`+`etag`), optional `--effective-routes`.
**Tests:** Tag-Ermittlung, Hub-Details und Service Tags über Fake-ArmReader (nur GET, `values`), 403-Isolation.

## Phase 5 — ursprüngliche Planung

**Deliverables:** `src/azure/arm` mit Enrichment-Plan aus dem RawInventory (E-FW-01, E-ER-01, E-VWAN-01…03, E-FD-01, E-MON-01, optional E-RT-01/E-NSG-01 laut RESOURCE-GRAPH-QUERIES § 11), Clients über `readOnlyClientOptions`, Cache (`resourceId`+`etag`), `EnrichmentResult` → `DiscoveryQuality.armEnrichment`, optional `--effective-routes`.
**Tests:** Plan-Ableitung (nur Lücken), 403 → Warnung, Cache-Hit, Concurrency-Grenze.

## Phase 6 — Normalisierung & Network Graph ◐

**Umgesetzt:** `src/normalization` (alle erfassten Typen inkl. `addressPrefix`/`addressPrefixes`-Merge, lowercase-IDs, Secret-Blocklist, generische Modellierung weiterer Typen, `unclassifiedNetworkResources`), `src/models/network.ts` (TS-Interfaces), `src/models/graph.ts` (Zod), `src/graph/buildGraph.ts` (Hierarchie, LOD, 13 Beziehungstypen, PE-NICs im Private Endpoint und VMSS-Instanz-NICs in der Scale Set zusammengefasst, externe/nicht lesbare Ziele als eigene Knoten), `src/topology/classify.ts` (Hub/Spoke/Shared/Standalone, NVA-Heuristik mit Konfidenz und Gründen), `src/pipeline/analyze.ts`.
**Real verifiziert:** 1 Hub (Konfidenz 1.0), 55 Spokes, 18 Standalone, 4 unklar; 3.662 Knoten, 6.896 Beziehungen, ~40 ms.
**Offen:**

- `Evidence`-Modell und `accessStatus`/`findingIds` am Graphknoten (ARCHITECTURE § 9) – wird mit Phase 9/11 eingeführt.
- Zod-Schemas für die normalisierten Entitäten (derzeit TS-Interfaces; Import prüft Sektionen strukturell).
- Tests: asymmetrische/Disconnected-Peerings, Subnet-Peering, vWAN-Hubs.

## Phase 7 — Topology UI + Tree View ◐

**Umgesetzt:** Statische SPA mit MSAL-Anmeldung und Discovery im Browser; React Flow + ELK (`elk-api` im Hauptthread, ELKs eigener `elk-worker.min.js` als Worker, Layout-Cache, Timeout); Level of Detail 1–5; Drilldown per Doppelklick (Container); Fokus mit Breadcrumb und Nachbarn; Tree View synchronisiert; Detail-Panel (Beziehungen, Peerings, Routen, NSG-/Firewall-Regeln inkl. `ipv6Rule`, DNS-Records, PE-Ziele, NAT-Egress, JSON-Ansicht/-Download); globale Suche inkl. IP/CIDR-Containment; Subscription-Filter; Mini-Map, Zoom, Fit View; Theme-Tokens Light/Dark; Übersicht mit Discovery Quality, Warnungen und Hinweisen.
**Real verifiziert:** Layout ≤ 0,2 s bis 1.234 Elemente; Sichtbarkeitsgrenze 1.500 Elemente mit Hinweis.
**Offen:**

- Dashboard-Kennzahlen nach Lastenheft § 58 (VNets nach IP-Klasse, Firewalls, NAT, VPN/ER, UDRs, PEs, Findings nach Severity).
- Filter Region, Resource Group, Resource Type, Hub/Spoke, Severity.
- Virtualisierter Tree View für sehr große Tenants (derzeit werden nur aufgeklappte Knoten gerendert).
- Komponententests (Testing Library) und automatisierter Performance-Test (≥ 2.000 Knoten).

## Phase 8 — IPv4/IPv6-Addressing ◐

**Umgesetzt:** `src/addressing/ip.ts` (Familienerkennung, bigint-Parsing inkl. `::`-Kompression und IPv4-mapped, `cidrContains`, Klassifikation, Default-Route-Erkennung); Klassifikation je Knoten; IP-Suche mit Containment; **IP-Modi IPv4 / IPv6 / Dual Stack** als Filter: passende Komponenten normal, verbundene und umschließende als Kontext im Hintergrund, übrige ausgeblendet.
**Offen:** kanonische RFC-5952-Schreibweise, Overlap-Erkennung (VNet-übergreifend, gepeerte VNets), IP-Index (Intervallbaum) und Suche im Worker, Adresskategorien (ULA/GUA/NAT64/RFC1918/CGNAT), Modus **Compare** (nach Phase 9).

## Phase 9 — Routing Path Analyzer ◐

**Umgesetzt** (Details ARCHITECTURE § 12.5):
- `src/routing/routes.ts`: Synthese der effektiven Routen je Subnet × Familie (VNet, Peering inkl. Subnet-Peering, Gateway-Präfixe aus LNGs, System-Defaults, reservierte None-Routen, UDRs); Auswahl per LPM mit UDR > BGP > System.
- `src/security/nsg.ts`: NSG-Evaluator mit Priorität, Default-Regeln, Service Tags `Internet`/`VirtualNetwork`/`AzureLoadBalancer`, CIDR je Familie, Ports, Protokolle, ASGs (ASG-Mitgliedschaft der NIC wird jetzt normalisiert); nicht auflösbare Tags senken die Konfidenz.
- `src/security/firewall.ts`: Policy-Hierarchie (Parent vor Child, RCG- und Collection-Priorität), Network Rules mit IP Groups, Application Rules als LIKELY/POSSIBLE, Default Deny; IPv6-Einschränkungen der Azure Firewall.
- `src/routing/trace.ts`: Path Tracer (Hop-Evidence, Status ALLOWED/BLOCKED/UNKNOWN/POTENTIAL_BYPASS, Schleifenerkennung, IP-Forwarding-Prüfung), Egress-Resolver, `compareFamilies` (Architecture Gap).
- `src/routing/analysis.ts`: Default-Internetpfad aller Workload-Subnets je Familie, IPv6-Bypass-Erkennung für Subnets und NICs.
- UI: „Pfadanalyse IPv4/IPv6“ im Detail-Panel (Ziel Internet oder IP, Protokoll, Port; Hops mit Begründung, Entscheidung, Konfidenz, Evidence; Hervorhebung im Graph mit nummerierten Pfadkanten); Ansicht „Internet-Pfade“ (Tabelle aller Subnets mit Filtern Bypass, ohne Kontrolle, IPv6); effektive Routen je Subnet.
- Export: `assessmentContext.internetEgressPaths`, `ipv4DefaultPaths`, `ipv6DefaultPaths`, `internetIngressPaths`, `knownArchitectureGaps` (IPV6_FIREWALL_BYPASS, IPV6_INBOUND_EXPOSURE, UNCONTROLLED_INBOUND_EXPOSURE, ASYMMETRIC_INBOUND_ROUTING).
- `src/routing/inbound.ts`: eingehende Pfade Internet → Workload über Instance-Public-IP, Public Load Balancer (Regeln, Inbound NAT), Application Gateway (Quelle = AppGW-Subnet, WAF = kontrolliert) und Azure-Firewall-DNAT (Quelle nach SNAT = Firewall-IP); AVNM + NSG je Port, offene vs. auf Quellbereiche eingeschränkte Ports, Erkennung asymmetrischen Routings (Rückweg per UDR über Appliance). UI: Umschalter „Ausgehend | Eingehend“ in „Internet-Pfade“, Abschnitt „Eingehend aus dem Internet“ in der Pfadanalyse.
- Virtual WAN: Routen aus Routing Intent (Private/Internet) bzw. assoziierter Hub Route Table + Propagation; Secured-Hub-Firewall mit Hub-Public-IPs; IPv6 nicht über den Hub.
- AVNM: Security-Admin-Regeln (neuester Snapshot, Deny/AlwaysAllow/Allow vor NSG) und Connected Groups (Mesh/Direct Connectivity) als Routen.
- ECMP: mehrere Next-Hop-IPs je UDR, Hop mit allen Zielen, Konfidenz sinkt bei gemischten/unbekannten Zielen.
- Service Tags: UDR-Tags werden zu Präfixen expandiert (spezifischer Tag gewinnt bei gleichem Präfix), NSG- und Firewall-Regeln lösen Tags über die Service-Tag-Daten auf.

**Real verifiziert:** 175 Default-Pfade in 31 ms; 66 IPv4-Subnets über Azure Firewall, 61 potenzieller Bypass, 2 NICs mit IPv6-Bypass. Eingehend: 38 Eingangspfade in 53 ms (35 Public IP, 3 Application Gateway), 16 offen ohne zentrale Kontrolle, 14 mit asymmetrischem Rückweg.

**Offen:** optionale Effective-Routes-API, AppGW-Backend-Port aus HTTP-Settings, vWAN Branch-/Hub-zu-Hub-Routing (BGP), Ost-West-Übersicht, UI-Komponententests.

**Tests:** Routen-Synthese IPv4/IPv6, Gateway-Routen und Propagation, LPM und Prioritäten, NSG (Priorität, Defaults, IPv6, Service Tags, ASG), Firewall (Allow, Default Deny, IPv6-Hinweis, fehlende Policy), Pfade (Firewall-Pfad, IPv6-Bypass, Vergleich, Peering, None-Route, NSG-Block, NAT, NAT Standard ohne IPv6, privates Subnet, Schleife), Default-Pfad-Analyse, Export; vWAN (Routing Intent, Hub Route Table, IPv6, fehlende Details), ECMP, Service-Tag-Expansion und -Präzedenz, AVNM (Snapshots, Casing, Connected Groups, Deny/AlwaysAllow), eingehende Pfade (Public IP, LB-Regel/NAT, eingeschränkte Quellen, asymmetrisches Routing, DNAT, Zielfilter).

## Phase 10 — Dual-Stack Gap Analysis ○

**Deliverables:** `src/dualstack` (Matrix pro VNet/Subnet mit Evidence, alle Gap-Typen, Readiness pro Kategorie ohne Gesamtscore), UI-Matrix und Readiness-Karten, Kennzeichnung „Dual Stack with Gap“ in Graph und Baum.
**Tests:** Vergleich je Zeile, Gap nur bei existierender Zweitfamilie, `UNKNOWN` statt `READY` bei fehlenden Daten.

## Phase 11 — Assessment Engine ○

**Deliverables:** `src/assessment` (Rule-Interface, Engine, stabile Finding-IDs, Severity-Kontext, Confidence-Degradierung), Regelkatalog (mind. Lastenheft §§ 51, 56), `architectureGaps[]`, Erweiterung `assessmentContext`, `ASSESSMENT-RULES.md`, `IPV6-ASSESSMENT.md`, UI (Findings-Liste, Findings im Detail-Panel, Graph-Layer).
**Tests:** je Regel positiv/negativ/unbekannt; **Akzeptanztests 1 und 2**.

## Phase 12 — Architecture Snapshots ◐

**Umgesetzt:** Jeder Export ist ein Snapshot (`snapshotMetadata`: `snapshotId`, `generatedAt`, Tenant-/Subscription-IDs, `resourceCount`); Import mit Zod-Prüfung (`schemaVersion` 0.x) und deterministischem Neuaufbau des Graphen aus dem Inventar; Offline-Analyse ohne Anmeldung.
**Offen:** `configurationHash`/`tagsHash`/`findingsHash` (kanonische Serialisierung), Schema-Migrationskette, Baseline-Datei („Approved Architecture Baseline“), CLI `snapshot`.
**Tests (offen):** Hash-Determinismus, volatile Felder ohne Einfluss, Roundtrip mit identischem Hash.

## Phase 13 — Semantic Diff / Drift ◐

**Umgesetzt:** `src/drift/diff.ts` – Vergleich Snapshot → aktueller Stand über Resource-IDs; Feld-Diff auf dem normalisierten Modell (NSG-Regeln, Routen, Links je Element); Drift-Kategorien; IPv4/IPv6-Bezug; Beziehungsänderungen; gelöschte, aber noch referenzierte Ressourcen als „entfernt“; Diff-Export `azure-network-diff-YYYYMMDD-HHMM.json`. UI: „Mit JSON vergleichen“, NEU/GEÄNDERT/ENTFERNT in Graph und Baum, Geister-Knoten, Δ-Zähler an Containern, Filter „Nur Änderungen“ (kombinierbar mit IP-Modus), Änderungsliste nach Kritikalität, Vorher/Nachher im Detail-Panel. Details: [SNAPSHOT-AND-DRIFT.md](SNAPSHOT-AND-DRIFT.md).
**Offen:** Finding-Lifecycle (NEW/RESOLVED/EXISTING/CHANGED, „Architecture Improvement“) nach Phase 11; abgeleitete Pfad-Änderungen („IPv6 bypass introduced“) nach Phase 9; `EXPECTED` über Baseline; Firewall-„relaxed“-Erkennung; Timeline; CLI `diff`.
**Tests:** Akzeptanztests 3, 5, 6 auf Diff-Ebene ✅, 4 als Routenänderung ✅ (Finding-Sicht offen), 7 offen; Tag = INFORMATIONAL ✅.

## Phase 14 — JSON Assessment Export ◐

**Umgesetzt:** `src/export/assessmentJson.ts` – Struktur nach Lastenheft § 60 (Metadaten, Snapshot-Metadaten, Summary, Discovery Quality/Warnungen, `assessmentContext` mit Architekturtyp, Regionen, zentralen Diensten, Hubs/Spokes; Adressierung je IPv4/IPv6; alle Inventarsektionen; kompakter Graph), Dateinamensschema, `metadata.coverage` für noch fehlende Analyseteile, CLI schreibt `output/network-assessment.json`. Diff-Export siehe Phase 13. Doku: [NETWORK-GRAPH-MODEL.md](NETWORK-GRAPH-MODEL.md).
**Offen:** Sektionen `dualStackAnalysis`, `assessment.findings`, `architectureGaps`, `internetEgressPaths`, `ipv4DefaultPaths`/`ipv6DefaultPaths` (nach Phasen 9–11); CSV-Inventar; JSON-Schema-Datei aus Zod; kompaktere KI-Variante (derzeit ~9 MB für den realen Tenant).

## Phase 15 — Draw.io Export ○

**Deliverables:** `src/export/drawio` (mxfile-XML, Layer, Kantenstile, Azure-Shapes, Positionen aus ELK in Node), SVG-Export, PNG (UI).
**Tests:** XML wohlgeformt, alle Layer, Kantenstile, eindeutige IDs, Golden File; manuelle Prüfung in diagrams.net.

## Phase 16 — Sanitization & Security ◐

**Umgesetzt:** `src/export/sanitize.ts` (`sanitizeExport`) – HMAC-SHA-256-Pseudonyme (Schlüssel wird pro Aufruf übergeben, nie gespeichert), präfixerhaltende Public-IP-Abbildung (RFC 5737/3849), ID-Umschreibung (auch in zusammengesetzten Graph-Kanten-IDs und Freitextfeldern über einen zweiten Whole-Word-Durchlauf), Ausnahme für Azure-Pflichtnamen (`AzureFirewallSubnet` u. Ä.), Secret-Feld-Entfernung unabhängig vom Wert als zweite Linie neben der bestehenden Normalisierungs-Blocklist. UI-Einstieg über den Button „KI-Analyse“ (§ 22 ARCHITECTURE.md).
**Real verifiziert:** Gegen die Hub-Spoke-Fixture – keine reale Subscription-/Resource-Group-/Resource-ID/-Name/Public-IP im sanitisierten Output, Struktur/Zählwerte/Präfixlängen/Graph-Kanten identisch, Determinismus über gleichen Schlüssel bestätigt.
**Offen:** CLI-Flag `--sanitize`/`--sanitize-key` (aktuell nur aus der Web-UI aufrufbar), `SECURITY.md` (Threat Model: MSAL-Tokens im Browser, CSP, Redirect-Bridge, Exporte, Read-only-Garantie, Azure-OpenAI-Key im Bundle – Risiken R20/R21 in ARCHITECTURE.md bereits vorgezogen dokumentiert).
**Tests:** `tests/export/sanitize.test.ts` – Determinismus, Schlüsselwechsel, keine Leckage (auch in zusammengesetzten IDs/Freitext), Plattformnamen bleiben erhalten, strukturelle Felder identisch, Public-IP-Ersetzung, Secret-Feld-Entfernung.

## Phase 22 — KI-Analyse (Azure OpenAI) ◐ *(neu, zahlt auf Lastenheft § 59–63 ein)*

**Umgesetzt:** `src/ai/azureOpenAi.ts` (Responses-API-Client, reiner `fetch`, kein SDK; Datei-Upload, Vector-Store-Erstellung/-Polling/-Löschung; Retry mit exponentiellem Backoff + `Retry-After`-Unterstützung auf `429`/`5xx` für alle Endpunkte, Standard 4 Versuche). `src/ai/analyze.ts` implementiert eine **Chat-Session auf `file_search`-Basis** (Details ARCHITECTURE.md § 22): der sanitisierte Export wird einmalig als Datei hochgeladen und in einem temporären Vector Store indiziert; jeder Chat-Turn (Sitzungsstart, Folgefragen, Report) läuft mit aktiviertem `file_search`-Tool gegen diesen Store und per `previous_response_id`-Chaining – das Modell ruft nur die für die jeweilige Frage relevanten Ausschnitte ab, statt den kompletten Export im Prompt zu tragen. „Report erzeugen“ kombiniert `file_search` mit Structured Outputs (`text.format: json_schema`, striktes Schema) zu einem typisierten `AiReport` (`summary`, `findings[]`, `recommendations[]`). `src/export/aiReportPdf.ts` rendert daraus clientseitig (`pdf-lib`, kein Server) ein herunterladbares PDF; JSON-Download bleibt zusätzlich verfügbar. UI-Panel `AiAnalysisPanel.tsx` ist ein Chat-Fenster mit gestaffelter Ladeanzeige: ein rotierendes Netzwerk-Schild-Icon mit Klartext-Status für normale Wartezeiten, zusätzlich fünf von der Mitte nach außen hüpfende Regenbogen-Punkte ab 4 Sekunden Wartezeit (typischerweise ein Rate-Limit-Retry). Schließen des Panels löscht Datei und Vector Store (`endSession`). Konfiguration weiterhin über `VITE_AZURE_OPENAI_ENDPOINT`/`_API_KEY`/`_MODEL` in `.env.local`.
**Performance-Fix im Sanitizer:** `sanitizeExport()` importierte den HMAC-Schlüssel früher pro pseudonymisiertem String neu (mehrere tausend `crypto.subtle.importKey`-Aufrufe bei einem großen Export). `Pseudonymizer.create()` importiert den Schlüssel jetzt einmal pro Lauf; Ergebnis unverändert (`tests/export/sanitize.test.ts` bleibt grün).
**Ingestion-Fix (`"Verarbeitung der hochgeladenen Datei fehlgeschlagen: An internal error occurred"`):** Azures eigene Datei-Verarbeitung schlug real mit `last_error.code = "server_error"` fehl. Gegenmaßnahmen: (1) `uploadFileSearchDocument()` formatiert den einzeiligen `JSON.stringify`-Export vor dem Upload zu mehrzeiligem, eingerücktem JSON um (eine sehr lange einzelne Zeile ist für die Text-Extraktion anfälliger) und lädt ihn mit MIME `text/plain` statt `application/json` hoch; (2) ein wiederholtes bloßes erneutes Anhängen derselben Datei reproduzierte den `server_error` in der Praxis identisch (der Fehler lag vermutlich am hochgeladenen Artefakt selbst, nicht an einer transienten Server-Bedingung) – bei einem Fehlschlag wird deshalb der **komplette Versuch verworfen** (Datei und Vector Store gelöscht) und mit einer **frischen** Datei/einem frischen Vector Store neu begonnen, bis zu zweimal, bevor der Fehler nach oben gereicht wird.
**Historie/verworfene Ansätze:** (1) ein Aufruf mit dem kompletten Export überschritt das Token-Rate-Limit (`HTTP 429 rate_limit_exceeded`, `gpt-5-mini`/`germanywestcentral`); (2) Batching (ein Aufruf je VNet) war bei ~80 VNets spürbar langsam; (3) eine Chat-Session, die den Export unverändert als erste Nachricht sendete, überschritt das Limit weiterhin, da der komplette Export weiterhin in einem Request steckte. `file_search` gegen einen temporären Vector Store löst das grundsätzlich, da der Export nie mehr vollständig Teil eines einzelnen Prompts ist.
**Fenster/UI-Umbau (Details ARCHITECTURE.md § 22.4):** Das Panel ist jetzt ein frei verschieb- und größenveränderbares Floating-Overlay statt eines festen Seitenbereichs. `src/ui/workspace/FloatingOverlay.tsx` (Titelleiste zum Ziehen, drei Resize-Griffe, Position/Größe in `localStorage` gemerkt und in den sichtbaren Bereich geklemmt) wird generisch verwendet und umschließt `AiAnalysisPanel.tsx`, das jetzt wie ein modernes Chat-Fenster aussieht (Sprechblasen statt Zeilen, eigene Composer-Zeile). Aus der Zwischenablage eingefügte Bilder (`onPaste`) werden als Base64-Data-URI der nächsten Chat-Nachricht als `input_image`-Inhalt beigefügt (`callAzureOpenAi({images})`, strukturiertes `input`-Array statt reinem String) – **nicht** in den Vector Store hochgeladen, da `file_search` nur textbasierte Dokumente indiziert. Die UI warnt sichtbar, sobald ein Bild angehängt ist, da es (anders als der Export) nicht durch `sanitizeExport()` läuft. Der Sanitizer-Schlüssel wird zur Bequemlichkeit in `localStorage` gemerkt (`ai-sanitizer-key`) und beim nächsten Öffnen vorausgefüllt (R22).
**Minimieren/Fortsetzen (Details ARCHITECTURE.md § 22.4):** `src/ui/workspace/aiSessionDirectory.ts` führt ein browserlokales (`localStorage`) Verzeichnis vergangener Sitzungen. Ein Eintrag ist `minimized` (Fenster geschlossen, aber Azure-OpenAI-Datei/Vector-Store bleiben bewusst am Leben, voller Chatverlauf inkl. `lastResponseId` persistiert, über das Sitzungsverzeichnis – auch nach einem Seiten-Reload – fortsetzbar via `resumeSession()`, keine Netzwerkaufrufe) oder `ended` (Nutzer hat explizit beendet, Datei/Vector-Store gelöscht, nur Metadaten bleiben als Historie). Der Azure-OpenAI-API-Key wird nie persistiert – `resumeSession()` baut `config` frisch aus den Umgebungsvariablen auf. Ein Klick auf einen fortsetzbaren Eintrag lädt die Sitzung vollständig zurück in die UI. Da ein minimierter Vector Store weiterlaufende `file_search`-Kosten verursacht (R23), weist das Sitzungsverzeichnis explizit darauf hin.
**Bewusste Entscheidung:** Läuft direkt aus dem Browser (kein eigenes Backend) – siehe ARCHITECTURE.md § 22.6 und Risiken R20 (Key im Bundle) und R21 (Restrisiko Re-Identifikation trotz Sanitizing). Der Vector Store ist bewusst so kurzlebig wie die Sitzung (Löschung beim Schließen), um die zusätzlichen `file_search`-Kosten zu begrenzen.
**Offen:** CLI-Äquivalent, Kostentracking am Client, Cross-VNet-Findings hängen von dem ab, was im Chat tatsächlich erfragt wurde (kein automatischer Vollständigkeits-Scan), Sitzungsverzeichnis ist nicht geräteübergreifend synchronisiert.
**Tests:** `tests/ai/azureOpenAi.test.ts` (HTTP-Contract, `file_search`-Tool-Aktivierung, Bild-Input als strukturiertes `input`-Array, `previous_response_id`-Chaining, `json_schema`-Structured-Output-Anfrage, Datei-Upload/Vector-Store-Erstellung/Anhängen/Polling/Löschung inkl. Fehlerfällen, Re-Indentierung vor dem Upload, Ingestion-Retry bei `server_error` mit komplett frischem Datei-/Vector-Store-Versuch statt bloßem Neu-Anhängen inkl. Cleanup des gescheiterten Versuchs und Erschöpfung aller Versuche, Retry bei 429 inkl. `Retry-After`-Header, Backoff-Grenze), `tests/ai/analyze.test.ts` (eindeutige lokale Sitzungs-ID, Sitzungsstart sendet nachweislich nur sanitisierte Daten in der hochgeladenen Datei, Fortschrittsphasen in der richtigen Reihenfolge, Cleanup bei fehlgeschlagenem Sitzungsstart, Folgenachrichten behalten `file_search` aktiv und senden nur die neue Nachricht plus optionale Bilder, Report-Erzeugung inkl. Schema-Anfrage und robustem JSON-Parsing/Fallback/Filterung ungültiger Findings, `endSession` löscht Datei und Vector Store, `resumeSession` rekonstruiert ohne Netzwerkaufruf und kann den Chat nahtlos fortsetzen), `tests/export/aiReportPdf.test.ts` (gültiges PDF-Signaturbyte, leerer Report, mehrseitiger Report mit langem Text), `tests/ui/workspace/aiSessionDirectory.test.ts` (Anlegen/Aktualisieren/Beenden von Einträgen, Titel-Kürzung, Sortierung nach Startzeit, `saveResumableSession`/`getResumableSession` inkl. Nachweis, dass der API-Key nie persistiert wird, Beenden löscht die fortsetzbaren Daten, robustes Verhalten ohne `localStorage`).

## Phase 17 — Tests (Konsolidierung) ◐

**Stand:** 138 Tests (Guard, SDK-Pipeline, ARG-Runner, Discovery, MSAL, Logging, CIDR, Normalisierung, Topologie, Graph, Sichtbarkeit/IP-Modi, Suche, Export/Import, Drift, ELK-Worker-Protokoll) auf synthetischen Fixtures.
**Offen:** `@vitest/coverage-v8` + Schwellen, Szenario-Fixtures (Dual-Stack mit Bypass, vWAN, NVA-HA), Suite `tests/acceptance` für Akzeptanztests 1–7, optionaler `npm run test:live` (read-only, Aggregat-Assertions).

## Phase 18 — Dokumentation ◐

**Vorhanden:** README, ARCHITECTURE, IMPLEMENTATION_PLAN, ENTRA-ID-SETUP, AZURE-DISCOVERY, RESOURCE-GRAPH-QUERIES, NETWORK-GRAPH-MODEL, SNAPSHOT-AND-DRIFT.
**Offen:** IPV6-ASSESSMENT, ASSESSMENT-RULES (Phase 11), SECURITY (Phase 16), `docs/ACCEPTANCE.md` (Abnahme-Checkliste entlang der Definition of Done).

---

## Akzeptanztest-Zuordnung

| Test | Szenario | Phase | Erwartung | Stand |
| --- | --- | --- | --- | --- |
| 1 | IPv4 `0.0.0.0/0→FW`, IPv6 `::/0→Internet` | 11 | NET-IPV6-003 HIGH/CRITICAL „IPv6 bypasses centralized firewall“ | ◐ Pfadebene: POTENTIAL_BYPASS + Architecture Gap; Finding offen |
| 2 | IPv4 zentrales NAT, IPv6 Public IP an VM | 11 | NET-NAT-001 + `SECURITY_GAP`/`EGRESS_GAP` | ◐ Pfadebene: IPv6-Egress über Instance-PIP erkannt; Finding offen |
| 3 | A IPv4-only, B IPv6-VNet-Präfix | 13 | ADDED IPv6 Address Space, ARCHITECTURE_RELEVANT | ✅ Diff-Test |
| 4 | A IPv6 ohne `::/0`-UDR, B `::/0→FW` | 13 | Finding RESOLVED, „Architecture Improvement“ | ◐ Routenänderung erkannt; Finding-Sicht offen |
| 5 | A NSG blockt IPv6-Internet, B allow `::/0` inbound | 13 | NEW Finding NET-NSG-001 HIGH/CRITICAL, SECURITY_RELEVANT | ◐ SECURITY_RELEVANT erkannt; Finding offen |
| 6 | A IPv4+IPv6 via Firewall, B IPv6-UDR entfernt | 13 | NEW Egress-/Firewall-Bypass-Finding, POTENTIALLY_BREAKING | ◐ POTENTIALLY_BREAKING erkannt; Finding offen |
| 7 | Finding in A, nicht in B | 13 | RESOLVED FINDING | ○ (nach Phase 11) |

## Traceability Lastenheft → Phase

| Lastenheft § | Phase | Stand |
| --- | --- | --- |
| 4–6 Read-only, Auth, RBAC | 4, 16 | ✅ Guard, MSAL, DefaultAzureCredential, RBAC-Doku |
| 7–8 Discovery-Pipeline | 3–5 | ◐ ARG fertig, ARM-Enrichment offen |
| 10–31 Ressourcen | 3–6 | ◐ ARG-Daten normalisiert; vWAN/Front-Door-Kinder offen |
| 32–35 Modell, Klassifikation, Hub/Spoke | 6, 8 | ◐ |
| 36–44 UI, Suche, Filter | 7, 8 | ◐ |
| 45–46 Path Trace | 9 | ◐ Trace, Evidence, Vergleich, UI |
| 47–54 Dual-Stack | 10 | ○ (IP-Modi als Vorstufe) |
| 55–57 Assessment | 11 | ○ |
| 58 Dashboard | 7, 11 | ◐ |
| 59–63 JSON/KI/Sanitize | 14, 16 | ◐ |
| 64–67 Draw.io/SVG/PNG/CSV | 14, 15 | ○ |
| 68–78 Snapshot/Drift/Diff | 12, 13 | ◐ |
| 79–81 UX/Performance | 7 | ◐ |
| 82 CLI | 4, 12–15 | ◐ nur `discover` |
| 83 Logging | 4 | ✅ Discovery-Events; Analyse-Events folgen |
| 84–85 Tests | alle, 17 | ◐ |
| 86–87 Doku | 3, 11, 13, 14, 16, 18 | ◐ |
| 89–91 Fehler/Confidence/Quality | 4, 5, 11 | ◐ Warnungen/Quality fertig; Finding-Confidence offen |
