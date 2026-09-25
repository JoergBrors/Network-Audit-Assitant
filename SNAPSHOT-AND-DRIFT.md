# SNAPSHOT-AND-DRIFT — Snapshots, Vergleich und Drift

Stand 2026-09-25 · Implementierung: `src/export/assessmentJson.ts`, `src/drift/diff.ts`, `src/ui/workspace/Changes.tsx` · Zielbild: [ARCHITECTURE.md § 16](ARCHITECTURE.md)

## 1. Snapshot = JSON-Export

Jeder Export `azure-network-assessment-YYYYMMDD-HHMM.json` ist ein Snapshot:

| Feld | Inhalt | Stand |
| --- | --- | --- |
| `metadata` | Tool, Version, `schemaVersion` (0.6.0), Exportzeit, `coverage` (enthaltene Analyseteile) | umgesetzt |
| `snapshotMetadata` | `snapshotId`, `generatedAt` (Discovery-Zeitpunkt), Tenant- und Subscription-IDs, `resourceCount` | umgesetzt |
| `snapshotMetadata.configurationHash` | deterministischer Hash ohne volatile Felder | geplant (Phase 12) |
| Inventar + Graph + Discovery Quality | siehe [NETWORK-GRAPH-MODEL.md](NETWORK-GRAPH-MODEL.md) | umgesetzt |

**Import** („JSON importieren“): Zod-Prüfung (eigenes Tool, `schemaVersion` 0.x), Übernahme des Inventars und deterministischer Neuaufbau des Graphen mit dem aktuellen Code. Funktioniert ohne Anmeldung (Offline-Analyse).

## 2. Vergleich („Mit JSON vergleichen“)

Vergleichsbasis ist der importierte Snapshot, Ziel der aktuell geladene Stand (Live-Discovery oder ein anderer Import). Ist die Basis neuer als der aktuelle Stand, weist die Vergleichsleiste darauf hin.

### 2.1 Algorithmus (`diffModels`)

1. **Match** über die normalisierte Resource-ID (Graphknoten ohne Tenant, Region, Internet und externe Platzhalter). Wird eine Ressource gelöscht, aber noch referenziert (z. B. durch ein Peering), erscheint sie im neuen Stand als externer Platzhalter und wird korrekt als **entfernt** gewertet.
2. **Feld-Diff** auf dem normalisierten Inventar-Eintrag (nicht auf JSON-Text):
   - Objekte feldweise
   - Listen mit `id` oder `name` (NSG-Regeln, Routen, VNet-Links, Rule Collections, …) je Element: hinzugefügt, entfernt, geändert
   - einfache Listen als Mengen (Reihenfolge ohne Bedeutung)
   - Pfade wie `rules[allow-https]` oder `addressSpace.ipv6`
3. **Beziehungen**: hinzugefügte und entfernte Kanten (ohne `contains`), z. B. neues Peering oder weggefallene `securedBy`-Absicherung.
4. **IPv4/IPv6-Bezug**: aus den geänderten Werten (bzw. den Adressen neuer/entfernter Ressourcen) und der Kantenfamilie.

### 2.2 Drift-Kategorien

| Kategorie | Regeln (Auszug) |
| --- | --- |
| `POTENTIALLY_BREAKING` | Default-Route hinzugefügt/entfernt; Routen-Präfix, Next Hop oder BGP-Propagation geändert; VNet-Address-Space entfernt oder geändert; Peering-Flags (`useRemoteGateways`, `allowGatewayTransit`, `allowForwardedTraffic`, Status) geändert; `securedBy` entfernt |
| `SECURITY_RELEVANT` | NSG-Regel neu/geändert mit Allow Inbound von `*`/`Internet`/`0.0.0.0/0`/`::/0`; Änderungen an NSGs, Firewalls, Policies, Rule Collection Groups, IP Groups, WAF, Public IPs, Private Endpoints; neue/entfernte `securedBy`-, `policyOf`-, NSG- und Public-IP-Zuordnungen; Routen-Kanten ins Internet |
| `ARCHITECTURE_RELEVANT` | neue/entfernte VNets, Subnets, Gateways, NAT, Load Balancer, DNS, Subscriptions; Änderungen an Topologie-Klassifikation oder NVA-Einstufung; neue Adressbereiche |
| `INFORMATIONAL` | reine Tag-Änderungen; Monitoring und generische Referenzen |
| `EXPECTED` | geplant (Auflösung von Baseline-Abweichungen) |

### 2.3 Darstellung

- **Vergleichsleiste:** Zeitpunkte, Anzahl neu/entfernt/geändert, Beziehungen ±, Hervorhebung „potenziell kritisch“ und „sicherheitsrelevant“, Anzahl IPv6-Änderungen.
- **Graph:**
  - NEU: grün, mit Leuchteffekt
  - GEÄNDERT: orange
  - ENTFERNT: roter, gestrichelter Geister-Knoten an der früheren Position, Name durchgestrichen
  - neue Beziehungen grün, entfernte rot gestrichelt
- **Δ n** an Containern (und im Baum): Anzahl der Änderungen darunter, damit Änderungen schon auf Detailstufe 1–2 auffallen.
- **„Nur Änderungen“:** Geänderte Elemente im Vordergrund, auch wenn die Änderung unterhalb der aktuellen Detailstufe liegt; Verbundenes als Kontext. Kombinierbar mit dem IP-Modus.
- **Änderungsliste** (rechts, solange nichts ausgewählt ist): nach Kategorie gruppiert, filterbar, anklickbar.
- **Detail-Panel:** Tabelle Feld → vorher → nachher (NSG-Regeln und Routen als lesbare Einzeiler).

## 3. Diff-Export

`azure-network-diff-YYYYMMDD-HHMM.json` nach Lastenheft § 78:

- `metadata`, `sourceSnapshot`, `targetSnapshot`
- `summary` inkl. `byCategory`; `newFindings`/`resolvedFindings` = `null` bis zur Assessment-Engine
- `resources.{added,removed,changed}`, `relationships`
- `networkChanges.{addressing,routing,peerings,firewall,nsg,nat,dns}`
- `ipv4Changes`, `ipv6Changes`, `assessment`

## 4. Grenzen und offene Punkte

- **Finding-Lifecycle** (NEW/RESOLVED/EXISTING/CHANGED, „Architecture Improvement“) folgt mit der Assessment-Engine (Phase 11); Akzeptanztests 4–7 sind bis dahin nur auf Konfigurationsebene abgedeckt.
- **Abgeleitete Pfad-Änderungen** („IPv6 bypass introduced“) folgen mit dem Routing Path Analyzer (Phase 9).
- **Kein Namens-Fallback** beim Matching: Eine neu angelegte Ressource mit gleichem Namen, aber neuer ID erscheint als entfernt + neu.
- `configurationHash`, Baseline-Markierung, Timeline und CLI `diff` sind geplant (Phasen 12/13).
- Importierte Inventare werden **nicht neu normalisiert** (nur der Graph wird neu aufgebaut). Stammen zwei Snapshots aus Tool-Versionen mit unterschiedlicher Normalisierung, können Felder als geändert erscheinen, die nur anders aufbereitet sind. Die Schema-Migrationskette (Phase 12) wird das abfangen.
