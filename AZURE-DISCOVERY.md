# AZURE-DISCOVERY — Discovery-Pipeline

Stand 2026-09-25 · Queries: [RESOURCE-GRAPH-QUERIES.md](RESOURCE-GRAPH-QUERIES.md) · Anmeldung: [ENTRA-ID-SETUP.md](ENTRA-ID-SETUP.md)

## 1. Ablauf

```
TokenCredential (MSAL im Browser | DefaultAzureCredential in der CLI)
  │
  ├─ 1. Tenants            GET /tenants                                   (arm-resources-subscriptions)
  ├─ 2. Subscriptions      GET /subscriptions  (je Tenant, tenant-gebundenes Token)
  │                        + Q-ORG-01 (ARG) für MG-Kette, Lighthouse, Resource Groups
  ├─ 3. Management Groups  Q-ORG-02 (ARG, MG-Scope = Tenant-ID)          optional
  ├─ 4. ARG-Queries        Katalog Q-*, je Tenant × Subscription-Batch × Query, Paging
  ├─ 5. RawInventory       Map<type, RawResource[]> + QueryStats
  ├─ 6. Enrichment-Plan    aus RawInventory abgeleitet (E-*), nur echte Lücken
  ├─ 7. ARM-Enrichment     GET-Calls mit Concurrency-Limit und Cache
  └─ 8. Ergebnis           RawInventory + EnrichmentResults + DiscoveryQuality + warnings[]
```

Die Pipeline ist **isomorph**: dieselben Module laufen in Node (CLI) und im Browser (Web-UI). Umgebungsabhängig sind nur zwei injizierte Adapter:
- `TokenCredential` (MSAL oder `DefaultAzureCredential`),
- `DiscoveryCache` (Datei in `.cache/` für die CLI, In-Memory pro Browser-Tab für die Web-UI).

## 2. Read-only-Garantie

Alle Azure-Clients entstehen über `createReadOnlyClient()`, das die Pipeline-Policy `readOnlyGuardPolicy` einsetzt:

| Methode | Verhalten |
| --- | --- |
| `GET`, `HEAD` | erlaubt |
| `POST …/providers/Microsoft.ResourceGraph/resources` | erlaubt (ARG-Abfrage) |
| `POST …/effectiveRouteTable`, `…/effectiveNetworkSecurityGroups` | nur wenn `allowEffectiveRoutes` explizit aktiv ist |
| alles andere (`PUT`, `PATCH`, `DELETE`, sonstige `POST`) | `ReadOnlyViolationError`, **bevor** der Request gesendet wird |

## 3. Scoping & Batching

- Subscriptions werden je Tenant in Batches (Default 200) an ARG übergeben.
- `Disabled`-Subscriptions werden nicht abgefragt (Warnung `SubscriptionDisabled`).
- Filter `--subscription`/UI-Auswahl reduziert den Scope vor der ersten ARG-Abfrage.
- Ein 403 auf einem Batch wird durch Halbierung eingegrenzt, bis die nicht lesbaren Subscriptions feststehen; lesbare Ergebnisse bleiben erhalten.

## 4. Throttling, Retry, Concurrency

| Mechanismus | Default |
| --- | --- |
| Parallele ARG-Requests | 4 |
| Parallele ARM-Requests | 8 |
| Retry | bis zu 5 Versuche, exponentiell (500 ms Basis, max. 30 s) + Jitter, für 429, 500, 502, 503, 504 und Netzwerkfehler |
| `Retry-After` | hat Vorrang vor dem berechneten Backoff |
| ARG-Quota | Header `x-ms-user-quota-remaining` / `x-ms-user-quota-resets-after`: bei Restquota ≤ 1 wird bis zum Reset pausiert |

## 5. Cache

- Key: `sha256(tenantId | query-id | query-version | sortierte Subscription-IDs)` bzw. für ARM `resourceId | operation | apiVersion`.
- TTL Default 15 Minuten, `--no-cache` bzw. „Neu laden“ in der UI umgeht den Cache.
- Inhalt: nur Ressourcendaten. Nie Tokens oder Header.
- Browser: nur im Arbeitsspeicher des Tabs, wird beim Abmelden und beim Schließen verworfen. Es werden keine Netzwerkdaten im Browser persistiert.

## 6. Fehlerisolation & Warnings

Jeder Fehler wird auf die kleinste Einheit begrenzt (Tenant → Batch → Subscription → Ressource) und erzeugt:

```json
{ "scope": "/subscriptions/…", "operation": "ARG:Q-NET-VNET", "reason": "InsufficientPermissions", "detail": "AuthorizationFailed" }
```

`reason`: `InsufficientPermissions | Throttled | NotFound | Truncated | TenantTokenUnavailable | SubscriptionDisabled | Error`.

## 7. Discovery Quality

| Kennzahl | Quelle |
| --- | --- |
| Tenants lesbar / gesamt | Token-Bezug je Tenant |
| Subscriptions lesbar / gesamt | `GET /subscriptions` vs. ARG-Batches ohne 403 |
| Netzwerkressourcen | Summe RawInventory (`microsoft.network/*` + VMSS-NICs) |
| ARG-Queries / Seiten / truncated / failed | QueryStats |
| ARM-Enrichment erfolgreich / nicht verfügbar | EnrichmentResults |
| Gesamt-Konfidenz | `HIGH`: alle Subscriptions lesbar, keine fehlgeschlagene Query, ≥ 98 % Enrichment ok; `MEDIUM`: ≥ 90 % Subscriptions und ≥ 90 % Enrichment; sonst `LOW` |

## 8. Logging

JSON-Lines-Events: `discovery.start`, `tenants.discovered`, `subscriptions.discovered`, `arg.query`, `arg.page`, `arm.enrichment`, `discovery.complete`. Redaction für `authorization`, `token`, `secret`, `key`, `password`, `sas`, `sig=`. Im Browser gehen die Logs in die Konsole (Level `info`+) und in das Diagnose-Panel.
