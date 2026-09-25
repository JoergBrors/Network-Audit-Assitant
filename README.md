# Azure Network Audit Assistant

Read-only Discovery, Topologie und IPv4/IPv6-Dual-Stack-Assessment für Azure-Netzwerklandschaften (Hub-and-Spoke, tenant- und subscriptionübergreifend).

> **Status:** Phasen 1–4 von 18 abgeschlossen (Architektur, Resource-Graph-Katalog, Anmeldung, Discovery). Normalisierung, Topologie, Routing, Dual-Stack-Analyse, Assessment und Exporte folgen gemäß [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Die vollständige Anleitung entsteht in Phase 18.

## Voraussetzungen

- Node.js ≥ 22
- Azure-Rolle **Reader** auf den zu analysierenden Subscriptions bzw. Management Groups
- CLI: eine Anmeldung, die `DefaultAzureCredential` findet (z. B. `az login`)
- Web-UI: eine Entra-ID-App-Registrierung vom Typ SPA, siehe [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md)

## Schnellstart

```bash
npm install

# CLI-Discovery (read-only) → output/raw-inventory.json
az login
npm run discover -- --credential cli
npm run discover -- --tenant <tenantId> --subscription <subId> --no-cache

# Web-UI mit Microsoft-Entra-Anmeldung (MSAL, Auth Code + PKCE)
cp .env.example .env.local   # VITE_ENTRA_CLIENT_ID eintragen
npm run dev                  # http://localhost:5173
```

## Qualität

```bash
npm run typecheck && npm run lint && npm test && npm run build
```

## Sicherheit

Das Tool ändert keine Azure-Ressourcen. Jeder Azure-Client läuft durch eine Pipeline-Policy, die alles außer `GET`/`HEAD` und der Resource-Graph-Abfrage blockiert, **bevor** ein Request gesendet wird. Tokens werden weder geloggt noch gespeichert oder exportiert. Details: [ARCHITECTURE.md § 4–5](ARCHITECTURE.md).

## Dokumentation

| Dokument | Inhalt |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Zielarchitektur, Datenmodell, Routing-/Dual-Stack-/Drift-Konzepte, Risiken |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Phasen, Deliverables, Akzeptanztests |
| [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md) | App-Registrierung, Berechtigungen, Consent, RBAC |
| [AZURE-DISCOVERY.md](AZURE-DISCOVERY.md) | Discovery-Pipeline, Throttling, Cache, Discovery Quality |
| [RESOURCE-GRAPH-QUERIES.md](RESOURCE-GRAPH-QUERIES.md) | Query-Katalog, ARG-Abdeckung, ARM-Enrichment |
