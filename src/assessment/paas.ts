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
    const category = PAAS_TYPE_INFO.get(s.azureType)?.category;
    // Front Door / CDN are public entry points by design; monitoring ingestion and AVD client access
    // are public by Microsoft default – reported, but lower.
    if (s.exposure === "public" && category !== "edge") {
      findings.push(
        finding(
          "paas",
          isSensitive(s) ? "HIGH" : category === "monitoring" || category === "vdi" ? "LOW" : "MEDIUM",
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
    findings.push(...ingressEgressFindings(s, label));
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

/** Findings from the ingress/egress profile (App Service SCM, AKS, Container Apps). */
function ingressEgressFindings(s: PaasServiceEntity, label: string): Finding[] {
  const out: Finding[] = [];
  const ingress = s.ingress;
  const egress = s.egress;
  if (!ingress || !egress) return out;
  const d = ingress.details;
  switch (s.azureType) {
    case "microsoft.web/sites": {
      const mainRules = ingress.rules.filter((r) => !r.scope);
      const scmRules = ingress.rules.filter((r) => r.scope === "SCM/Kudu");
      const scmDefault = d["Standardaktion SCM"];
      const restrictive = (list: typeof mainRules) =>
        list.some((r) => r.action === "Allow" && r.source !== "Any");
      const scmRestricted = restrictive(scmRules) || scmDefault === "wie Haupt-Site" || scmDefault === "Deny";
      if (s.publicNetworkAccess === "Enabled" && restrictive(mainRules) && !scmRestricted)
        out.push(
          finding(
            "paas",
            "MEDIUM",
            "WEB_SCM_UNRESTRICTED",
            `${label}: Haupt-Site eingeschränkt, SCM/Kudu-Endpunkt aber offen`,
            "Der Deployment-Endpunkt (*.scm.azurewebsites.net) hat eigene Zugriffsregeln. „Gleiche Regeln wie Haupt-Site“ aktivieren oder eigene SCM-Regeln setzen.",
            [s.id],
          ),
        );
      if (egress.mode === "vnet-partial")
        out.push(
          finding(
            "paas",
            "LOW",
            "WEB_EGRESS_NOT_ROUTED",
            `${label}: VNet-Integration ohne „Route All“`,
            "Nur private Ziele gehen über das integrierte Subnet; Internet-Verkehr nutzt die Plattform-Ausgangs-IPs und umgeht UDR/Firewall. „Outbound internet traffic“ (Route All) aktivieren, wenn der Ausgang kontrolliert werden soll.",
            [s.id, ...egress.subnetIds],
          ),
        );
      break;
    }
    case "microsoft.containerservice/managedclusters": {
      if (ingress.mode === "internet")
        out.push(
          finding(
            "paas",
            "MEDIUM",
            "AKS_PUBLIC_WORKLOAD_INGRESS",
            `${label}: Workloads über öffentliche Frontends erreichbar`,
            `${d["Öffentliche LB-Frontends mit Regeln"] ?? "?"} öffentliche Load-Balancer-Frontend(s)${d["Application Gateway Ingress (AGIC)"] ? " bzw. Application Gateway (AGIC)" : ""}. Prüfen, ob die Services (Typ LoadBalancer / Ingress) öffentlich sein sollen; sonst interne Load Balancer oder WAF davor.`,
            [s.id, ...(s.links ?? []).filter((l) => l.direction === "ingress").map((l) => l.id)],
          ),
        );
      if (egress.mode === "load-balancer" || egress.mode === "nat-gateway")
        out.push(
          finding(
            "paas",
            "LOW",
            "AKS_EGRESS_NOT_CONTROLLED",
            `${label}: Ausgang über ${egress.mode === "nat-gateway" ? "NAT Gateway" : "Load Balancer (SNAT)"}`,
            "Ausgehender Cluster-Verkehr geht über die Ausgangs-IPs des Clusters direkt ins Internet, nicht über eine zentrale Firewall. Für kontrollierten Egress Outbound-Typ „userDefinedRouting“ mit Azure Firewall/NVA verwenden. Liegt am Knoten-Subnet bereits eine UDR 0.0.0.0/0 zur Firewall, entsteht mit diesem Outbound-Typ asymmetrisches Routing.",
            [s.id],
          ),
        );
      break;
    }
    case "microsoft.app/managedenvironments":
      if (egress.mode === "azure-default" && egress.subnetIds.length)
        out.push(
          finding(
            "paas",
            "LOW",
            "ACA_EGRESS_NOT_CONTROLLABLE",
            `${label}: Consumption-only-Umgebung – Ausgang nicht über UDR steuerbar`,
            "Nur Umgebungen mit Workload Profiles unterstützen UDR und NAT Gateway für den Internet-Ausgang.",
            [s.id],
          ),
        );
      break;
    case "microsoft.app/containerapps":
      if (d["HTTP erlaubt (allowInsecure)"] === "ja" && ingress.mode.startsWith("internet"))
        out.push(
          finding(
            "paas",
            "LOW",
            "ACA_INSECURE_HTTP",
            `${label}: unverschlüsseltes HTTP am externen Ingress erlaubt`,
            "„allowInsecure“ deaktivieren, damit HTTP auf HTTPS umgeleitet wird.",
            [s.id],
          ),
        );
      break;
  }
  return out;
}
