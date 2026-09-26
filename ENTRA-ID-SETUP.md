# Entra ID Setup — Anmeldung der Web-UI mit MSAL

Die Web-UI meldet Benutzer per **MSAL.js (Authorization Code Flow mit PKCE)** an und fordert ein Access Token für **Azure Resource Manager** an. Mit diesem Token werden ARM und Azure Resource Graph direkt aus dem Browser **ausschließlich lesend** abgefragt.

Die CLI braucht **keine** App-Registrierung, sie verwendet `DefaultAzureCredential` (z. B. `az login`).

---

## 1. Überblick: welche Berechtigung wofür?

| Ebene | Was | Wert | Wer muss es einrichten |
| --- | --- | --- | --- |
| Entra ID: App-Registrierung | Plattform **Single-page application (SPA)** mit Redirect-URI(s) auf die **Redirect-Bridge-Seite** | z. B. `http://localhost:5173/redirect.html` | App-Administrator (oder jeder Benutzer, der App-Registrierungen anlegen darf) |
| Entra ID: API-Berechtigung (delegiert) | **Azure Resource Manager → `user_impersonation`** | Scope `https://management.azure.com/user_impersonation` | wie oben; Zustimmung siehe § 4 |
| Entra ID: OIDC-Scopes | `openid`, `profile`, `offline_access` | fordert MSAL automatisch an | – |
| **Azure RBAC** (entscheidet, *was* gelesen werden kann) | **`Reader`** auf Management Groups oder Subscriptions | eingebaute Rolle | Owner/User Access Administrator der Scopes |
| Entra ID: API-Berechtigung (delegiert, nur für KI-Analyse) | **Azure Cognitive Services → `user_impersonation`** | Token-Scope `https://cognitiveservices.azure.com/.default` | wie oben; siehe § 8.1 |
| Azure RBAC (nur für KI-Analyse) | **`Cognitive Services OpenAI User`** auf der Azure-OpenAI-Ressource | eingebaute Rolle | Owner/User Access Administrator der Ressource |
| Azure RBAC (optional) | Management-Group-Hierarchie | `Reader` bzw. `Management Group Reader` auf der Root/MG | wie oben |

Referenzwerte der Berechtigung (in jedem Tenant gleich):

| Eigenschaft | Wert |
| --- | --- |
| Ressource | Azure Resource Manager (früher „Azure Service Management“) |
| Resource AppId | `797f4846-ba00-4fd7-ba43-dac1f8f63013` |
| Delegierter Scope | `user_impersonation` |
| Scope-ID | `41094075-9dad-400e-a0bd-54e686782033` |
| Consent-Typ | „User“: Benutzer können selbst zustimmen, sofern die Tenant-Richtlinie Benutzerzustimmung erlaubt |

**Nicht benötigt:** Client Secret, Zertifikat, Application Permissions (App-only), Microsoft Graph `User.Read`, Azure Key Vault `user_impersonation`, Implicit Grant (Access-/ID-Tokens), „Allow public client flows“.

> **Wichtig: `user_impersonation` ist kein reiner Lese-Scope.** ARM kennt keinen Read-only-Scope. Das Token darf alles, was die RBAC-Rollen des Benutzers erlauben. Die Anwendung selbst ist technisch read-only: Eine HTTP-Pipeline-Policy blockiert `PUT`, `PATCH` und `DELETE` sowie jedes `POST` außer der Resource-Graph-Abfrage, bevor ein Request gesendet wird. Trotzdem wird empfohlen, das Tool mit Konten bzw. Gruppen zu verwenden, die nur **`Reader`** besitzen (siehe § 5).

---

## 2. App-Registrierung im Entra Admin Center

1. <https://entra.microsoft.com> → **Identity → Applications → App registrations → New registration**.
2. **Name:** z. B. `Azure Network Audit Assistant`.
3. **Supported account types:**
   - *Accounts in this organizational directory only (Single tenant)*: wenn nur Subscriptions eines Tenants analysiert werden.
   - *Accounts in any organizational directory (Multitenant)*: wenn Benutzer auch Subscriptions in **anderen Tenants** analysieren sollen (Gast-Zugriffe). Siehe § 6.
4. **Redirect URI:** Plattform **Single-page application (SPA)**, Wert `http://localhost:5173/redirect.html` (Vite-Dev-Server). Weitere URIs für `npm run preview` (`http://localhost:4173/redirect.html`) und die produktive Hosting-URL (`https://<host>/redirect.html`, nur `https`) ergänzen.
   - **Warum `/redirect.html`?** MSAL.js v5 verlangt für Popup-, Silent- und Redirect-Flows eine eigene **Redirect-Bridge-Seite**, die nur `broadcastResponseToMainFrame()` ausführt und die Antwort an das Hauptfenster weiterreicht. Zeigt die Redirect-URI auf die App selbst, lädt das Popup die ganze App und die Anmeldung scheitert mit `no_token_request_cache_error`.
   - Die Bridge-Seite darf **nicht** mit einem `Cross-Origin-Opener-Policy`-Header ausgeliefert werden.
   - Der Typ **muss** „SPA“ sein, nicht „Web“. Sonst schlägt die Token-Einlösung mit einem CORS-Fehler fehl (`AADSTS9002326`).
5. **Register** → **Application (client) ID** notieren (und bei Single-Tenant die **Directory (tenant) ID**).
6. **Authentication:** Unter *Implicit grant and hybrid flows* **beide** Checkboxen **deaktiviert** lassen. *Allow public client flows* = **No**.
7. **API permissions → Add a permission → APIs my organization uses** (bzw. *Microsoft APIs*) → **Azure Resource Manager** (in älteren Portalen *Azure Service Management*) → **Delegated permissions** → **`user_impersonation`** → **Add permissions**.
8. Optional: `Microsoft Graph → User.Read` entfernen, wenn es automatisch hinzugefügt wurde. Das Tool benötigt es nicht.
9. **Certificates & secrets:** nichts anlegen.

---

## 3. Alternative: Registrierung per Azure CLI

```bash
# 1) App anlegen (Single-Tenant; für Multi-Tenant: --sign-in-audience AzureADMultipleOrgs)
APP_ID=$(az ad app create \
  --display-name "Azure Network Audit Assistant" \
  --sign-in-audience AzureADMyOrg \
  --required-resource-accesses '[{
      "resourceAppId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
      "resourceAccess": [{ "id": "41094075-9dad-400e-a0bd-54e686782033", "type": "Scope" }]
    }]' \
  --query appId -o tsv)

# 2) SPA-Redirect-URIs setzen (az ad app create hat dafür keinen Parameter → Microsoft Graph)
OBJ_ID=$(az ad app show --id "$APP_ID" --query id -o tsv)
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJ_ID" \
  --headers "Content-Type=application/json" \
  --body '{"spa":{"redirectUris":["http://localhost:5173/redirect.html","http://localhost:4173/redirect.html"]}}'

# 3) Service Principal (Enterprise Application) im eigenen Tenant anlegen
az ad sp create --id "$APP_ID"

echo "VITE_ENTRA_CLIENT_ID=$APP_ID"
echo "VITE_ENTRA_AUTHORITY=https://login.microsoftonline.com/$(az account show --query tenantId -o tsv)"
```

Diese Befehle **ändern Entra ID** (sie legen eine App-Registrierung an). Sie gehören nicht zum Tool, sondern sind die einmalige, manuelle Einrichtung durch einen Administrator.

---

## 4. Zustimmung (Consent)

- `user_impersonation` ist ein **benutzerzustimmungsfähiger** Scope. Beim ersten Login fragt Entra ID den Benutzer um Zustimmung, **sofern** die Tenant-Einstellung *Enterprise applications → Consent and permissions → User consent settings* das erlaubt.
- Viele Unternehmen deaktivieren die Benutzerzustimmung. Dann muss ein **Cloud Application Administrator**, **Application Administrator** oder **Privileged Role Administrator** einmalig zustimmen:
  - Portal: *App registrations → \<App\> → API permissions → **Grant admin consent for \<Tenant\>***
  - oder CLI: `az ad app permission admin-consent --id "$APP_ID"`
- Die Zustimmung erlaubt der App nur, **im Namen des angemeldeten Benutzers** zu handeln. Sie gewährt **keinen** Zugriff auf Azure-Ressourcen. Den regelt ausschließlich Azure RBAC (§ 5).

---

## 5. Azure RBAC: was der Benutzer lesen darf

| Zweck | Rolle | Scope | Pflicht |
| --- | --- | --- | --- |
| Netzwerk-Discovery (ARG + ARM-GET) | **Reader** | Management Group (empfohlen, vererbt sich) oder einzelne Subscriptions | **ja** |
| Management-Group-Hierarchie anzeigen | **Reader** oder **Management Group Reader** | Tenant Root Group / MGs | optional |
| Effective Routes / Effective NSG pro NIC (präzisere Routing-Analyse) | Custom Role mit `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` und `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | Subscriptions | optional, im Tool standardmäßig **aus** |

Empfehlung:

- Eine Entra-Gruppe, z. B. `sg-network-audit-readers`, erhält `Reader` auf der obersten relevanten Management Group.
- **Kein** Contributor oder Owner für Audit-Benutzer. Hat ein Benutzer zusätzlich Schreibrechte, verhindert das Tool trotzdem Schreibzugriffe (§ 1), das Token selbst wäre aber mächtiger.

Beispiel für eine Custom Role (optional):

```json
{
  "Name": "Network Audit Effective Routes Reader",
  "IsCustom": true,
  "Description": "Allows reading effective routes and effective NSG rules of network interfaces.",
  "Actions": [
    "Microsoft.Network/networkInterfaces/effectiveRouteTable/action",
    "Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action"
  ],
  "NotActions": [],
  "AssignableScopes": ["/providers/Microsoft.Management/managementGroups/<mg-id>"]
}
```

Fehlen Rechte, bricht das Tool **nicht** ab. Es markiert betroffene Ressourcen als `not-accessible`, erzeugt `warnings[]` und zeigt die Vollständigkeit unter *Discovery Quality*.

---

## 6. Mehrere Tenants

Das Tool listet alle Tenants des angemeldeten Benutzers (`GET /tenants`) und fordert **pro Tenant ein eigenes Token** an (Authority `https://login.microsoftonline.com/<tenantId>`). Voraussetzungen je weiterem Tenant:

1. App-Registrierung ist **Multitenant** (`AzureADMultipleOrgs`), `VITE_ENTRA_AUTHORITY=https://login.microsoftonline.com/organizations`.
2. Im fremden Tenant existiert nach Zustimmung ein **Service Principal** der App. Das passiert beim ersten Login mit Benutzerzustimmung, sonst per Admin-Consent-URL:
   `https://login.microsoftonline.com/<fremderTenantId>/adminconsent?client_id=<APP_ID>`
3. Der Benutzer hat dort `Reader` (§ 5).
4. Conditional Access/MFA des fremden Tenants wird erfüllt. Das Tool öffnet bei Bedarf ein Popup.

Kann für einen Tenant kein Token bezogen werden, erscheint eine Warnung `TenantTokenUnavailable`; alle anderen Tenants werden weiter analysiert.

Azure-Lighthouse-delegierte Subscriptions benötigen **keine** Zustimmung im Kunden-Tenant; sie sind mit dem Token des eigenen Tenants lesbar.

---

## 7. Absicherung (empfohlen)

- **Enterprise Application → Properties → Assignment required = Yes**, dann Benutzer/Gruppe (z. B. `sg-network-audit-readers`) unter *Users and groups* zuweisen.
- **Conditional Access** für die App (MFA, konforme Geräte).
- Nur `https`-Redirect-URIs in Produktion; `localhost` nur für Entwicklung.
- Hosting mit strikter **Content Security Policy**:
  `default-src 'self'; connect-src 'self' https://login.microsoftonline.com https://management.azure.com; frame-src https://login.microsoftonline.com; script-src 'self'; object-src 'none'; base-uri 'self'`
  Mit KI-Analyse ergänzt der Build den Azure-OpenAI-Endpunkt automatisch in `connect-src` (`vite.config.ts`).

---

## 8. Konfiguration der Web-UI

Datei `.env.local` (nicht einchecken; Vorlage `.env.example`):

```bash
VITE_ENTRA_CLIENT_ID=<Application (client) ID>
# Single-Tenant:  https://login.microsoftonline.com/<tenantId>
# Multi-Tenant:   https://login.microsoftonline.com/organizations  (Default)
VITE_ENTRA_AUTHORITY=https://login.microsoftonline.com/organizations
```

Client-ID und Authority sind **keine Geheimnisse**. Sie stehen im ausgelieferten JavaScript, so wie bei jeder SPA.

Token-Verhalten:

- Token-Cache: `sessionStorage` (wird mit dem Tab geschlossen); die App persistiert, loggt oder exportiert keine Tokens.
- Access Tokens für ARM gelten ca. 60–90 Minuten; SPA-Refresh-Tokens 24 Stunden. Danach ist eine erneute interaktive Anmeldung (Popup) nötig.

### 8.1 KI-Analyse mit Azure OpenAI (optional)

Die KI-Analyse ruft das interne Azure-OpenAI-Deployment ohne API-Schlüssel mit dem Konto des angemeldeten Benutzers auf. Das ist die von Microsoft empfohlene Variante. Einrichtung:

1. **App-Registrierung → API permissions → Add a permission → APIs my organization uses → „Azure Cognitive Services“** → **Delegated → `user_impersonation`**. Danach Admin-Consent erteilen oder die Benutzerzustimmung zulassen (§ 4). Die Anwendung fordert den Scope `https://cognitiveservices.azure.com/.default` an. Die Azure v1 API akzeptiert auch `https://ai.azure.com/.default`, das lässt sich per `VITE_AZURE_OPENAI_SCOPE` einstellen.
2. **Azure-OpenAI-Ressource → Access control (IAM):** Den Benutzern oder der Gruppe (z. B. `sg-network-audit-readers`) die Rolle **`Cognitive Services OpenAI User`** zuweisen. Die Rolle erlaubt Inferenz sowie Dateien und Antworten, aber keine Verwaltung der Ressource.
3. `.env.local`:

```bash
VITE_AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
VITE_AZURE_OPENAI_MODEL=<deployment>          # z. B. gpt-5-mini
# optional: Token-Scope (Standard https://cognitiveservices.azure.com/.default)
VITE_AZURE_OPENAI_SCOPE=
# optional: minimal | low | medium | high (Standard für Reasoning-Modelle: low)
VITE_AZURE_OPENAI_REASONING_EFFORT=
# leer lassen: Entra ID. Nur als Rückfall ohne Anmeldung (landet im Bundle!):
VITE_AZURE_OPENAI_API_KEY=
```

Die Anwendung fordert das Token beim ersten KI-Aufruf still an; fehlt die Zustimmung, erscheint einmalig ein Popup. Der Export wird **unverändert** übertragen, daher nur ein für diese Daten freigegebenes internes Deployment verwenden (ARCHITECTURE.md § 22, Risiko R21).

---

## 9. Fehlerbehebung

| Fehler | Ursache | Lösung |
| --- | --- | --- |
| `AADSTS50011` redirect URI mismatch | `<Origin>/redirect.html` (inkl. Port) ist nicht als SPA-Redirect-URI registriert | URI unter *Authentication → Single-page application* ergänzen |
| `no_token_request_cache_error` / Popup bleibt hängen | Redirect-URI zeigt auf die App statt auf die Bridge-Seite `/redirect.html` | Redirect-URI auf `/redirect.html` ändern; Tab schließen oder `sessionStorage` leeren und neu anmelden |
| `AADSTS9002326` Cross-origin token redemption… | Redirect-URI ist vom Typ „Web“ statt „SPA“ | URI auf Plattform SPA migrieren |
| `AADSTS65001` consent required | Benutzerzustimmung deaktiviert, kein Admin-Consent | Admin-Consent erteilen (§ 4) |
| `AADSTS700016` application not found in directory | Single-Tenant-App, Login in fremdem Tenant; oder kein Service Principal im Ziel-Tenant | App auf Multitenant umstellen und Admin-Consent im Ziel-Tenant (§ 6) |
| `AADSTS50105` user not assigned | „Assignment required“ aktiv, Benutzer nicht zugewiesen | Benutzer/Gruppe der Enterprise App zuweisen |
| Login ok, aber keine Subscriptions | Keine RBAC-Rolle | `Reader` zuweisen (§ 5) |
| KI-Analyse: `401`/`403` von Azure OpenAI | Rolle „Cognitive Services OpenAI User“ fehlt oder API-Berechtigung ohne Zustimmung | § 8.1 Schritt 1–2; nach Rollenzuweisung einige Minuten warten |
| KI-Analyse: `404` | Deployment-Name falsch oder Endpunkt ohne v1-API | `VITE_AZURE_OPENAI_MODEL` = Deployment-Name, Endpunkt ohne Pfad angeben |
| KI-Analyse im Build: „Failed to fetch“ | Build ohne `VITE_AZURE_OPENAI_ENDPOINT`, CSP blockiert den Endpunkt | Mit gesetztem Endpunkt neu bauen |
| Popup wird blockiert | Browser-Popup-Blocker | Popups für die UI-URL erlauben; das Tool fällt auf Redirect zurück |
