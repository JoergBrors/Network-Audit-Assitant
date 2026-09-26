import type { NormalizedInventory, PaasServiceEntity } from "../models/network.js";
import { PAAS_TYPE_INFO } from "../models/paasCatalog.js";
import { lastSegment } from "../utils/ids.js";
import type { PeDnsCheck } from "./dns.js";
import { finding, type Finding } from "./types.js";

export interface PaasSummary {
  total: number;
  byExposure: Record<PaasServiceEntity["exposure"], number>;
  withPrivateEndpoint: number;
  withVnetIntegration: number;
}

const WEAK_TLS = /^(tls)?1[._]?[01]$/i;

/** Services whose control plane or data is especially sensitive when publicly reachable. */
const isSensitive = (s: PaasServiceEntity) =>
  PAAS_TYPE_INFO.get(s.azureType)?.sensitive === true ||
  s.azureType === "microsoft.containerservice/managedclusters";

export function assessPaas(
  inv: NormalizedInventory,
  peDns: PeDnsCheck[],
): { summary: PaasSummary; findings: Finding[] } {
  const findings: Finding[] = [];
  const dnsByTarget = new Map<string, PeDnsCheck[]>();
  for (const c of peDns) dnsByTarget.set(c.targetId, [...(dnsByTarget.get(c.targetId) ?? []), c]);

  for (const s of inv.paasServices) {
    const label = `${s.service} ${s.name}`;
    if (s.exposure === "public") {
      findings.push(
        finding(
          "paas",
          isSensitive(s) ? "HIGH" : "MEDIUM",
          "PAAS_PUBLIC_OPEN",
          `${label}: öffentlicher Endpunkt ohne Einschränkung`,
          `${s.exposureReasons.join("; ")}. Erreichbar über ${s.endpoints.slice(0, 3).join(", ") || "den öffentlichen Endpunkt"}. Empfehlung: öffentlichen Zugriff deaktivieren (Private Endpoint) oder auf bekannte Quellen einschränken.`,
          [s.id],
        ),
      );
    }
    if (s.privateEndpointIds.length > 0 && s.publicNetworkAccess === "Enabled" && s.exposure !== "private") {
      findings.push(
        finding(
          "paas",
          "MEDIUM",
          "PAAS_PUBLIC_WITH_PRIVATE_ENDPOINT",
          `${label}: Private Endpoint vorhanden, öffentlicher Zugriff aber weiter aktiv`,
          "Der Dienst ist parallel über das Internet erreichbar. Wenn nur private Nutzung vorgesehen ist, „Public network access“ deaktivieren.",
          [s.id, ...s.privateEndpointIds],
        ),
      );
    }
    if (
      s.exposure === "restricted" &&
      s.firewall.bypass &&
      /azureservices/i.test(s.firewall.bypass) &&
      isSensitive(s)
    ) {
      findings.push(
        finding(
          "paas",
          "LOW",
          "PAAS_AZURE_SERVICES_BYPASS",
          `${label}: Ausnahme „Azure-Dienste“ erlaubt`,
          "Jeder Azure-Dienst – auch aus fremden Tenants – passiert die Firewall. Nur aktivieren, wenn benötigt.",
          [s.id],
        ),
      );
    }
    if (s.exposure === "unknown") {
      findings.push(
        finding(
          "paas",
          "INFO",
          "PAAS_EXPOSURE_UNKNOWN",
          `${label}: Erreichbarkeit nicht bestimmbar`,
          `${s.exposureReasons.join("; ")}.`,
          [s.id],
        ),
      );
    }
    for (const c of s.privateEndpointConnectionStates) {
      findings.push(
        finding(
          "paas",
          "MEDIUM",
          "PAAS_PRIVATE_ENDPOINT_NOT_APPROVED",
          `${label}: Private-Endpoint-Verbindung ${lastSegment(c.privateEndpointId)} ist „${c.status}“`,
          "Nur genehmigte Verbindungen leiten Verkehr weiter.",
          [s.id, c.privateEndpointId],
        ),
      );
    }
    if (s.minimumTlsVersion && WEAK_TLS.test(s.minimumTlsVersion)) {
      findings.push(
        finding(
          "paas",
          "MEDIUM",
          "PAAS_WEAK_TLS",
          `${label}: Mindest-TLS-Version ${s.minimumTlsVersion}`,
          "TLS 1.0/1.1 gelten als unsicher; Mindestversion 1.2 setzen.",
          [s.id],
        ),
      );
    }
    const broken = (dnsByTarget.get(s.id) ?? []).filter((c) =>
      ["missing-zone", "missing-record", "not-linked"].includes(c.status),
    );
    if (broken.length > 0 && s.publicNetworkAccess === "Disabled") {
      findings.push(
        finding(
          "paas",
          "HIGH",
          "PAAS_UNREACHABLE_PRIVATE_DNS",
          `${label}: nur privat erreichbar, aber die private DNS-Auflösung ist unvollständig`,
          "Clients lösen den Namen auf die öffentliche IP auf, der öffentliche Zugriff ist gesperrt – Verbindungen schlagen fehl. Details in der DNS-Prüfung der Private Endpoints.",
          [s.id, ...new Set(broken.map((c) => c.privateEndpointId))],
        ),
      );
    }
  }

  const byExposure = { private: 0, restricted: 0, public: 0, unknown: 0 };
  for (const s of inv.paasServices) byExposure[s.exposure]++;
  return {
    summary: {
      total: inv.paasServices.length,
      byExposure,
      withPrivateEndpoint: inv.paasServices.filter((s) => s.privateEndpointIds.length > 0).length,
      withVnetIntegration: inv.paasServices.filter((s) => s.vnetIntegration.subnetIds.length > 0).length,
    },
    findings,
  };
}
