# Azure Network Audit Assistant

Read-only Discovery, Topologie, Snapshot-Vergleich und (in Arbeit) IPv4/IPv6-Dual-Stack-Assessment für Azure-Netzwerklandschaften: Hub-and-Spoke, tenant- und subscriptionübergreifend.

> **Status (2026-09-25):** Discovery, normalisiertes Modell, Hub/Spoke-Erkennung, interaktive Topologie mit Drilldown, IP-Modi, **Routing-/Pfadanalyse mit IPv4/IPv6-Vergleich (ausgehend und eingehend, inkl. Virtual WAN, AVNM, ECMP, Service Tags)**, JSON-Export/-Import und Snapshot-Vergleich sind nutzbar. Dual-Stack-Gap-Analyse, Findings, Draw.io und Sanitizing folgen. Details: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Voraussetzungen

- Node.js ≥ 22
- Azure-Rolle **Reader** auf den zu analysierenden Subscriptions bzw. Management Groups
- **CLI:** eine Anmeldung, die `DefaultAzureCredential` findet (z. B. `az login`)
- **Web-UI:** Entra-ID-App-Registrierung vom Typ SPA mit Redirect-URI `http://localhost:5173/redirect.html`, siehe [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md)

## Installation und Start

```bash
npm install

# Web-UI (Anmeldung per Microsoft Entra ID, MSAL Auth Code + PKCE)
cp .env.example .env.local   # VITE_ENTRA_CLIENT_ID (und ggf. VITE_ENTRA_AUTHORITY) eintragen
npm run dev                  # http://localhost:5173

# Produktions-Build (statische Dateien in dist/, inkl. Content Security Policy)

```

## Web-UI

| Funktion | Bedienung |
| --- | --- |
| Discovery | „Anmelden“ → „Discovery starten“: alle erreichbaren Tenants und Subscriptions über Azure Resource Graph, nur lesend |
| Topologie | Detailstufe 1–5 ohne Größenlimit (semantischer Zoom: Übersicht → Namen → Details beim Hineinzoomen), Elementtyp-Filter (z. B. nur VMs & PaaS, Hierarchie bleibt), Tag-Filter (`key=value`), Doppelklick = aufklappen (Drilldown), „Fokus“ im Detailbereich, Mini-Map, Zoom |
| Baum | Tenant → Subscription → Region → VNet → Subnet → Ressourcen, synchron mit dem Graphen |
| Details | Adressen, Hub/Spoke-Begründung, Beziehungen, Peerings, Routen, NSG-/Firewall-Regeln, DNS-Records, JSON |
| Suche | Name, Resource ID, IP-Adresse oder CIDR (findet NIC/VM sowie enthaltendes Subnet/VNet) |
| IP-Modus | IPv4 / IPv6 / Dual Stack: passende Komponenten vorne, Verbundenes blass als Kontext, Rest ausgeblendet |
| Pfadanalyse | Subnet/VM/NIC wählen → „Pfadanalyse IPv4/IPv6“: Weg ins Internet oder zu einer IP je Familie, Hop für Hop mit Route, NSG-/Firewall-Entscheidung, Egress, Konfidenz und Evidence; „Im Graph zeigen“ hebt den Pfad hervor. Darunter „Eingehend aus dem Internet“: welche Public IPs, Load Balancer, Application Gateways oder Firewall-DNAT-Regeln die Ressource erreichen |
| Internet-Pfade | Umschalter über dem Graphen: „Ausgehend“: Tabelle aller Subnets mit Status (erlaubt, blockiert, unklar, potenzieller Bypass), erster Route, Egress und Kontrolle. „Eingehend“: alle Eingangspfade aus dem Internet mit offenen bzw. eingeschränkten Ports, Kontrolle (Firewall/WAF) und asymmetrischem Rückweg |
| Effektive Routen | Detailbereich eines Subnets: rekonstruierte Routen je Familie mit Quelle und Konfidenz |
| Übersicht & Qualität | Bewertung von PaaS-Endpunkten und DNS: Befunde nach Schwere, Erreichbarkeit jedes PaaS-Dienstes (Storage, SQL, Key Vault, App Service, AKS, …), DNS-Server je VNet, Private-DNS-Zonen, DNS Private Resolver und Regelsätze, DNS-Prüfung jedes Private Endpoints; dazu Discovery-Qualität |
| JSON exportieren | `azure-network-assessment-YYYYMMDD-HHMM.json` (normalisiertes Inventar + Beziehungsgraph) |
| JSON importieren | früheren Export offline laden (ohne Anmeldung) |
| Mit JSON vergleichen | früheren Export als Basis: NEU / GEÄNDERT / ENTFERNT im Graphen, Δ-Zähler, „Nur Änderungen“, Diff-Export |
| KI-Analyse | optional, internes Azure-OpenAI-Deployment (Anmeldung per Entra ID): Chat über den unveränderten Export mit Code Interpreter und Streaming, Dateien/Bilder anhängen, erzeugte Dateien herunterladen, Report als PDF/JSON. Einrichtung: [ENTRA-ID-SETUP.md § 8.1](ENTRA-ID-SETUP.md) |

## CLI

```bash
az login
npm run discover -- --credential cli
npm run discover -- --tenant <tenantId> --subscription <subId> --no-cache --log-level warn
npm run discover -- --credential cli --no-enrichment   # ohne ARM-Enrichment (vWAN-Hub-Details, Service Tags)
npm run verify:arg -- --credential cli      # welche Properties ARG je Typ liefert (nur Aggregate)
```

Ausgabe in `output/`:

- `raw-inventory.json`: Rohdaten, nur lokal zur Fehlersuche
- `network-assessment.json` und `azure-network-assessment-YYYYMMDD-HHMM.json`: normalisierter Export, zugleich Snapshot

Exit-Code 0 bedeutet vollständig, 2 abgeschlossen mit Warnungen, 1 Fehler.

## Qualität

```bash
npm run typecheck && npm run lint && npm test && npm run build
```

## Sicherheit

Das Tool ändert keine Azure-Ressourcen. Jeder Azure-Client läuft durch eine Pipeline-Policy, die alles außer `GET`/`HEAD` und der Resource-Graph-Abfrage blockiert, **bevor** ein Request gesendet wird. Tokens werden weder geloggt noch persistiert (MSAL-Cache nur in `sessionStorage`) noch exportiert. Details: [ARCHITECTURE.md § 4–5](ARCHITECTURE.md), [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md).

## Dokumentation

| Dokument | Inhalt |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Zielarchitektur mit Umsetzungsstand je Abschnitt, Risiken |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Phasen, Status, offene Punkte, Akzeptanztests |
| [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md) | App-Registrierung, Berechtigungen, Consent, RBAC, Fehlerbehebung |
| [AZURE-DISCOVERY.md](AZURE-DISCOVERY.md) | Discovery-Pipeline, Throttling, Cache, Discovery Quality |
| [RESOURCE-GRAPH-QUERIES.md](RESOURCE-GRAPH-QUERIES.md) | Query-Katalog, ARG-Abdeckung, ARM-Enrichment |
| [NETWORK-GRAPH-MODEL.md](NETWORK-GRAPH-MODEL.md) | Normalisiertes Modell, Knoten, Beziehungen, Heuristiken, Sichtbarkeit |
| [SNAPSHOT-AND-DRIFT.md](SNAPSHOT-AND-DRIFT.md) | Snapshots, Vergleich, Drift-Kategorien, Diff-Export |
npm run build && npm run preview