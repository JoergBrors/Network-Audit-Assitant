import type { Enrichment } from "../models/discovery.js";
import type {
  PaasAccessRule,
  PaasEgress,
  PaasEgressMode,
  PaasIngress,
  PaasIngressMode,
  PaasLink,
  PaasServiceEntity,
} from "../models/network.js";
import { normalizeId } from "../utils/ids.js";
import { arr, bool, num, obj, str, strings, type Obj } from "./access.js";

type PaasRules = NonNullable<Enrichment["paasNetworkRules"]>[string];

/**
 * Cross-resource hints collected while normalizing one service, resolved once the whole inventory is
 * known (container app → environment, AKS → node resource group, host pool → session host VMs).
 */
export interface PaasLinkHints {
  environmentId?: string | undefined;
  environmentInternal?: boolean | undefined;
  workloadProfiles?: boolean | undefined;
  aksNodeResourceGroup?: string | undefined;
  aksOutboundIpIds?: string[] | undefined;
  aksAppGatewayId?: string | undefined;
  aseId?: string | undefined;
  sessionHostVmIds?: string[] | undefined;
  applicationGroupIds?: string[] | undefined;
  publicIpIds?: string[] | undefined;
  privateLinkScopeIds?: string[] | undefined;
}

export const LINK_HINTS = new WeakMap<PaasServiceEntity, PaasLinkHints>();

const yesNo = (v: boolean | undefined) => (v === undefined ? undefined : v ? "ja" : "nein");

/** Keeps only defined, non-empty values. */
function details(values: Record<string, string | number | boolean | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(values)) {
    if (v === undefined || v === "") continue;
    out[k] = typeof v === "boolean" ? (v ? "ja" : "nein") : String(v);
  }
  return out;
}

function ids(...values: unknown[]): string[] {
  return [...new Set(values.flatMap((v) => (normalizeId(str(v)) ? [normalizeId(str(v))!] : [])))];
}

function ruleAction(value: unknown): "Allow" | "Deny" {
  return str(value)?.toLowerCase() === "deny" ? "Deny" : "Allow";
}

/** App Service `ipSecurityRestrictions` / `scmIpSecurityRestrictions` entries. */
function webRestrictions(list: unknown, scope?: string): PaasAccessRule[] {
  return arr(list).flatMap((r) => {
    const o = obj(r);
    const source =
      str(o["ipAddress"]) ??
      normalizeId(str(o["vnetSubnetResourceId"])) ??
      (str(o["tag"]) ? str(o["tag"]) : undefined);
    if (!source) return [];
    const headers = obj(o["headers"]);
    const fdid = strings(headers["x-azure-fdid"]);
    return [
      {
        name: [str(o["name"]), fdid.length ? `x-azure-fdid: ${fdid.join(", ")}` : ""]
          .filter(Boolean)
          .join(" · "),
        source: source.toLowerCase() === "any" ? "Any" : source,
        action: ruleAction(o["action"]),
        priority: num(o["priority"]),
        ...(scope ? { scope } : {}),
      },
    ];
  });
}

/** The `web` configuration of a site: "Web Apps - Get Configuration" names it after the app. */
export function webConfigOf(rules: PaasRules | undefined): Obj | undefined {
  const list = (rules?.siteConfig ?? []).map((c) => obj(c));
  const web =
    list.find((c) => str(c["id"])?.toLowerCase().endsWith("/config/web")) ??
    list.find((c) => str(c["name"])?.toLowerCase() === "web") ??
    (list.length === 1 ? list[0] : undefined);
  return web ? obj(web["properties"]) : undefined;
}

/** Firewall rules as ARM lists them (SQL/PostgreSQL/MySQL/Synapse: start/endIpAddress; Redis: startIP/endIP). */
function armRangeRules(list: unknown[]): PaasAccessRule[] {
  return list.flatMap((r) => {
    const o = obj(r);
    const p = obj(o["properties"]);
    const start = str(p["startIpAddress"]) ?? str(p["startIP"]);
    const end = str(p["endIpAddress"]) ?? str(p["endIP"]);
    if (!start) return [];
    const range = end && end !== start ? `${start}-${end}` : start;
    const azure = range === "0.0.0.0" || range === "0.0.0.0-0.0.0.0";
    return [
      {
        name: str(o["name"]),
        source: azure ? "AzureServices (0.0.0.0)" : range,
        action: "Allow" as const,
      },
    ];
  });
}

function defaultIngressMode(e: PaasServiceEntity): PaasIngressMode {
  if (e.publicNetworkAccess === "Disabled") {
    if (e.privateEndpointIds.length) return "private-endpoint";
    if (e.vnetIntegration.mode === "injection" && e.vnetIntegration.subnetIds.length) return "vnet";
    return "none";
  }
  if (e.publicNetworkAccess === "Unknown" && e.firewall.source === "none") return "unknown";
  if (e.firewall.source === "none") return "unknown";
  return e.firewall.defaultAction === "Deny" ? "internet-restricted" : "internet";
}

export const INGRESS_LABEL: Record<PaasIngressMode, string> = {
  internet: "Internet, offen",
  "internet-restricted": "Internet, eingeschränkt",
  vnet: "nur aus dem VNet",
  "private-endpoint": "nur über Private Endpoint",
  none: "kein eingehender Endpunkt",
  unknown: "nicht ermittelbar",
};

export const EGRESS_LABEL: Record<PaasEgressMode, string> = {
  "azure-default": "Plattform-Ausgang (nicht steuerbar)",
  vnet: "gesamter Verkehr über Kunden-Subnet",
  "vnet-partial": "nur private Ziele über Kunden-Subnet",
  "managed-vnet": "Managed VNet (Microsoft-verwaltet)",
  "load-balancer": "AKS Load Balancer (SNAT)",
  "nat-gateway": "NAT Gateway",
  udr: "User Defined Routing (UDR)",
  none: "kein kundenseitiger Ausgang",
  unknown: "nicht ermittelbar",
};

/** Services that do not initiate customer traffic (data/secret stores, telemetry sinks). */
const NO_EGRESS = new Set([
  "microsoft.storage/storageaccounts",
  "microsoft.keyvault/vaults",
  "microsoft.documentdb/databaseaccounts",
  "microsoft.containerregistry/registries",
  "microsoft.appconfiguration/configurationstores",
  "microsoft.servicebus/namespaces",
  "microsoft.eventhub/namespaces",
  "microsoft.insights/components",
  "microsoft.operationalinsights/workspaces",
  "microsoft.insights/privatelinkscopes",
  "microsoft.recoveryservices/vaults",
  "microsoft.web/staticsites",
  "microsoft.fabric/privatelinkservicesforfabric",
  "microsoft.powerbi/privatelinkservicesforpowerbi",
  "microsoft.desktopvirtualization/workspaces",
  "microsoft.sql/servers",
  "microsoft.dbforpostgresql/flexibleservers",
  "microsoft.dbformysql/flexibleservers",
  "microsoft.cache/redis",
]);

function ingressSummary(mode: PaasIngressMode, e: PaasServiceEntity, extra?: string): string {
  const ways = [
    e.privateEndpointIds.length ? `${e.privateEndpointIds.length} Private Endpoint(s)` : "",
    extra ?? "",
  ].filter(Boolean);
  return `${INGRESS_LABEL[mode]}${ways.length ? ` · ${ways.join(" · ")}` : ""}`;
}

/** Rules from the normalized firewall (IP and subnet rules are allow rules). */
function firewallRules(e: PaasServiceEntity): PaasAccessRule[] {
  return [
    ...e.firewall.ipRules.map((ip) => ({ source: ip, action: "Allow" as const })),
    ...e.firewall.subnetIds.map((s) => ({ source: s, action: "Allow" as const, name: "VNet-Regel" })),
  ];
}

interface Built {
  ingress: PaasIngress;
  egress: PaasEgress;
  links: PaasLink[];
  hints: PaasLinkHints;
}

/**
 * Ingress and egress configuration per service, read from the properties Microsoft documents for
 * each resource provider (REST API reference / networking concept pages). Values the ARM API does not
 * expose (Kubernetes ingress objects, Fabric tenant settings) are named as such in the summary.
 */
export function buildPaasNetwork(
  type: string,
  p: Obj,
  e: PaasServiceEntity,
  rules: PaasRules | undefined,
): Built {
  const links: PaasLink[] = [];
  const hints: PaasLinkHints = {};
  const link = (id: string | undefined, label: string, direction: PaasLink["direction"]) => {
    const n = normalizeId(id);
    if (n && !links.some((l) => l.id === n && l.label === label)) links.push({ id: n, label, direction });
  };
  let ingressMode = defaultIngressMode(e);
  let ingressExtra: string | undefined;
  let ingressRules = firewallRules(e);
  let ingressDetails: Record<string, string> = {};
  let ingressIps: string[] = [];

  const subnets = e.vnetIntegration.subnetIds;
  let egressMode: PaasEgressMode = NO_EGRESS.has(type)
    ? "none"
    : e.vnetIntegration.mode === "injection" && subnets.length
      ? "vnet"
      : "azure-default";
  let egressExtra: string | undefined;
  let egressSubnets = e.vnetIntegration.mode === "injection" ? [...subnets] : [];
  let egressIps = [...e.outboundIps];
  let allowedTargets: string[] | undefined;
  let egressDetails: Record<string, string> = {};

  switch (type) {
    // --- App Service / Functions / Logic Apps Standard ------------------------------------------------
    case "microsoft.web/sites": {
      const config = webConfigOf(rules) ?? obj(p["siteConfig"]);
      const main = webRestrictions(config["ipSecurityRestrictions"]);
      const scmUsesMain = bool(config["scmIpSecurityRestrictionsUseMain"]) === true;
      const scm = scmUsesMain ? [] : webRestrictions(config["scmIpSecurityRestrictions"], "SCM/Kudu");
      if (main.length || scm.length || webConfigOf(rules)) ingressRules = [...main, ...scm];
      const routing = obj(p["outboundVnetRouting"]);
      const routeAll =
        bool(routing["allTraffic"]) ?? bool(p["vnetRouteAllEnabled"]) ?? bool(config["vnetRouteAllEnabled"]);
      const imagePull =
        bool(routing["imagePullTraffic"]) ??
        bool(p["vnetImagePullEnabled"]) ??
        bool(config["vnetImagePullEnabled"]);
      const contentShare = bool(routing["contentShareTraffic"]) ?? bool(p["vnetContentShareEnabled"]);
      ingressDetails = details({
        Art: str(p["kind"]) ?? e.kind,
        "Nur HTTPS": bool(p["httpsOnly"]),
        "Mindest-TLS": str(config["minTlsVersion"]),
        "Mindest-TLS (SCM)": str(config["scmMinTlsVersion"]),
        "Client-Zertifikat": bool(p["clientCertEnabled"])
          ? (str(p["clientCertMode"]) ?? "Required")
          : bool(p["clientCertEnabled"]) === false
            ? "aus"
            : undefined,
        "Standardaktion Haupt-Site": str(config["ipSecurityRestrictionsDefaultAction"]),
        "Standardaktion SCM": scmUsesMain
          ? "wie Haupt-Site"
          : str(config["scmIpSecurityRestrictionsDefaultAction"]),
        FTP: str(config["ftpsState"]),
        "Remote-Debugging": bool(config["remoteDebuggingEnabled"]),
        "Eigene Hostnamen":
          strings(p["hostNames"]).length > 1 ? strings(p["hostNames"]).join(", ") : undefined,
      });
      const ase = normalizeId(str(obj(p["hostingEnvironmentProfile"])["id"]));
      if (ase) {
        hints.aseId = ase;
        link(ase, "App Service Environment", "other");
      }
      if (subnets.length) {
        egressMode = routeAll ? "vnet" : "vnet-partial";
        egressSubnets = [...subnets];
      }
      egressDetails = details({
        "VNet-Integration": subnets.length ? "ja" : "nein",
        "Gesamter Ausgang über VNet (Route All)": subnets.length ? yesNo(routeAll ?? false) : undefined,
        "Image-Pull über VNet": subnets.length ? yesNo(imagePull) : undefined,
        "Content-Share über VNet": subnets.length ? yesNo(contentShare) : undefined,
      });
      if (!subnets.length || !routeAll)
        egressExtra = `Internet-Ziele über ${egressIps.length} mögliche Plattform-Ausgangs-IP(s)`;
      break;
    }
    case "microsoft.web/hostingenvironments": {
      const ilb = str(p["internalLoadBalancingMode"]) ?? "None";
      const networking = obj(obj(rules?.extra?.["networking"]?.[0])["properties"]);
      const aseSubnet = ids(obj(p["virtualNetwork"])["id"]);
      ingressMode = ilb.toLowerCase() === "none" ? "internet" : "vnet";
      ingressIps = [
        ...strings(networking["externalInboundIpAddresses"]),
        ...strings(networking["internalInboundIpAddresses"]),
      ];
      ingressDetails = details({
        "Interner Load Balancer": ilb,
        "Neue Private-Endpoint-Verbindungen": bool(networking["allowNewPrivateEndpointConnections"]),
        FTP: bool(networking["ftpEnabled"]),
        "Remote-Debugging": bool(networking["remoteDebugEnabled"]),
      });
      egressMode = "vnet";
      egressSubnets = aseSubnet;
      egressIps = [
        ...strings(networking["windowsOutboundIpAddresses"]),
        ...strings(networking["linuxOutboundIpAddresses"]),
      ];
      break;
    }
    case "microsoft.logic/workflows": {
      const access = obj(p["accessControl"]);
      const trig = arr(obj(access["triggers"])["allowedCallerIpAddresses"]);
      ingressRules = trig.flatMap((r) =>
        str(obj(r)["addressRange"])
          ? [{ source: str(obj(r)["addressRange"])!, action: "Allow" as const, scope: "Trigger" }]
          : [],
      );
      const content = arr(obj(access["contents"])["allowedCallerIpAddresses"]);
      ingressRules.push(
        ...content.flatMap((r) =>
          str(obj(r)["addressRange"])
            ? [{ source: str(obj(r)["addressRange"])!, action: "Allow" as const, scope: "Run-Historie" }]
            : [],
        ),
      );
      ingressMode = trig.length ? "internet-restricted" : "internet";
      const endpoints = obj(p["endpointsConfiguration"]);
      egressIps = [
        ...arr(obj(endpoints["workflow"])["outgoingIpAddresses"]),
        ...arr(obj(endpoints["connector"])["outgoingIpAddresses"]),
      ].flatMap((x) => strings([obj(x)["address"]]));
      egressMode = "azure-default";
      break;
    }

    // --- Container Apps ---------------------------------------------------------------------------------
    case "microsoft.app/managedenvironments": {
      const vnet = obj(p["vnetConfiguration"]);
      const internal = bool(vnet["internal"]) === true;
      const profiles = arr(p["workloadProfiles"]);
      hints.environmentInternal = internal;
      hints.workloadProfiles = profiles.length > 0;
      ingressIps = strings([p["staticIp"]]);
      ingressMode =
        e.publicNetworkAccess === "Disabled"
          ? e.privateEndpointIds.length
            ? "private-endpoint"
            : internal
              ? "vnet"
              : "none"
          : internal
            ? "vnet"
            : "internet";
      ingressDetails = details({
        Umgebungstyp: profiles.length ? `Workload Profiles (${profiles.length})` : "Consumption only",
        Zugänglichkeit: internal ? "intern (interner Load Balancer)" : "extern (öffentliche IP)",
        "Statische IP": str(p["staticIp"]),
        "Standard-Domain": str(p["defaultDomain"]),
        "Plattform-CIDR": str(vnet["platformReservedCidr"]),
        "Docker-Bridge-CIDR": str(vnet["dockerBridgeCidr"]),
        "Peer-Verschlüsselung (mTLS)":
          bool(obj(obj(p["peerTrafficConfiguration"])["encryption"])["enabled"]) ??
          bool(obj(obj(p["peerAuthentication"])["mtls"])["enabled"]),
        "Eigene DNS-Suffix": str(obj(p["customDomainConfiguration"])["dnsSuffix"]),
        "Infrastruktur-Resource-Group": str(p["infrastructureResourceGroup"]),
      });
      if (subnets.length) {
        egressSubnets = [...subnets];
        if (profiles.length) egressMode = "vnet";
        else {
          egressMode = "azure-default";
          egressExtra =
            "Consumption-only-Umgebung: Internet-Ausgang über Plattform-IP, UDR/NAT Gateway werden nicht unterstützt";
        }
      } else {
        egressMode = "azure-default";
        egressExtra = "ohne eigenes VNet (Microsoft-verwaltetes Netz)";
      }
      egressDetails = details({ "Infrastruktur-Subnet": subnets[0] });
      break;
    }
    case "microsoft.app/containerapps":
    case "microsoft.app/jobs": {
      const env = normalizeId(str(p["managedEnvironmentId"]) ?? str(p["environmentId"]));
      if (env) {
        hints.environmentId = env;
        link(env, "Container Apps Environment", "other");
      }
      const ingress = obj(obj(p["configuration"])["ingress"]);
      egressIps = strings(p["outboundIpAddresses"]);
      egressMode = "unknown";
      if (type === "microsoft.app/jobs" || Object.keys(ingress).length === 0) {
        ingressMode = "none";
        ingressRules = [];
        ingressExtra = type === "microsoft.app/jobs" ? "Job ohne Ingress" : "Ingress deaktiviert";
        break;
      }
      ingressRules = arr(ingress["ipSecurityRestrictions"]).flatMap((r) => {
        const o = obj(r);
        const range = str(o["ipAddressRange"]);
        return range ? [{ name: str(o["name"]), source: range, action: ruleAction(o["action"]) }] : [];
      });
      const external = bool(ingress["external"]) === true;
      ingressMode = external
        ? ingressRules.some((r) => r.action === "Allow")
          ? "internet-restricted"
          : "internet"
        : "vnet";
      if (!external) ingressExtra = "Ingress intern: nur innerhalb der Container Apps Environment";
      const ports = arr(ingress["additionalPortMappings"]).map((m) => {
        const o = obj(m);
        return `${num(o["exposedPort"]) ?? num(o["targetPort"]) ?? "?"}→${num(o["targetPort"]) ?? "?"}${bool(o["external"]) ? " (extern)" : " (intern)"}`;
      });
      ingressDetails = details({
        Ingress: external ? "extern" : "intern",
        Transport: str(ingress["transport"]),
        "Ziel-Port": num(ingress["targetPort"]),
        "Exponierter Port": num(ingress["exposedPort"]),
        "HTTP erlaubt (allowInsecure)": bool(ingress["allowInsecure"]),
        "Client-Zertifikat": str(ingress["clientCertificateMode"]),
        "Weitere Ports": ports.join(", ") || undefined,
        "Eigene Domains": arr(ingress["customDomains"])
          .flatMap((d) => strings([obj(d)["name"]]))
          .join(", "),
        "CORS-Origins": strings(obj(ingress["corsPolicy"])["allowedOrigins"]).join(", "),
        FQDN: str(ingress["fqdn"]),
        "IP-Regeln ohne Allow":
          ingressRules.length && !ingressRules.some((r) => r.action === "Allow")
            ? "nur Deny-Regeln"
            : undefined,
      });
      break;
    }

    // --- AKS --------------------------------------------------------------------------------------------
    case "microsoft.containerservice/managedclusters": {
      const api = obj(p["apiServerAccessProfile"]);
      const net = obj(p["networkProfile"]);
      const addons = obj(p["addonProfiles"]);
      const agic = obj(addons["ingressApplicationGateway"] ?? addons["ingressapplicationgateway"]);
      const agicConfig = obj(agic["config"]);
      const agicId = normalizeId(
        str(agicConfig["effectiveApplicationGatewayId"]) ?? str(agicConfig["applicationGatewayId"]),
      );
      const httpRouting = obj(addons["httpApplicationRouting"] ?? addons["httpapplicationrouting"]);
      const webApp = obj(obj(p["ingressProfile"])["webAppRouting"]);
      const nginx = str(obj(webApp["nginx"])["defaultIngressControllerType"]);
      const istio = obj(obj(p["serviceMeshProfile"])["istio"]);
      const istioGateways = arr(obj(istio["components"])["ingressGateways"])
        .map((g) => obj(g))
        .filter((g) => bool(g["enabled"]) !== false)
        .map((g) => str(g["mode"]) ?? "?");
      const pools = arr(p["agentPoolProfiles"]).map((a) => obj(a));
      const privateCluster = bool(api["enablePrivateCluster"]) === true;
      const authorized = strings(api["authorizedIPRanges"]);
      hints.aksNodeResourceGroup = str(p["nodeResourceGroup"])?.toLowerCase();
      if (agicId && bool(agic["enabled"]) !== false) {
        hints.aksAppGatewayId = agicId;
        link(agicId, "Application Gateway (AGIC)", "ingress");
      }
      for (const z of strings(webApp["dnsZoneResourceIds"])) link(z, "DNS-Zone (App Routing)", "ingress");
      if (str(api["privateDNSZone"])?.startsWith("/"))
        link(str(api["privateDNSZone"]), "Private DNS Zone (API-Server)", "ingress");
      ingressRules = authorized.map((r) => ({ source: r, action: "Allow" as const, scope: "API-Server" }));
      // Workload ingress mode is refined from the node resource group's load balancers when linking.
      ingressMode = "unknown";
      ingressExtra = `API-Server: ${
        privateCluster
          ? "privat"
          : authorized.length
            ? `öffentlich, ${authorized.length} autorisierte Bereiche`
            : "öffentlich, offen"
      }`;
      ingressDetails = details({
        "API-Server privat (Private Cluster)": privateCluster,
        "API-Server VNet-Integration": bool(api["enableVnetIntegration"]),
        "Öffentlicher FQDN trotz Private Cluster": privateCluster
          ? bool(api["enablePrivateClusterPublicFQDN"])
          : undefined,
        "Autorisierte IP-Bereiche": authorized.join(", ") || (privateCluster ? undefined : "keine (offen)"),
        "App Routing (verwaltetes NGINX)": bool(webApp["enabled"])
          ? `aktiv${nginx ? ` · Standard-Controller: ${nginx}` : ""}`
          : undefined,
        "Application Gateway Ingress (AGIC)": bool(agic["enabled"]) ? "aktiv" : undefined,
        "Istio Ingress Gateways": istioGateways.join(", ") || undefined,
        "HTTP Application Routing (veraltet)": bool(httpRouting["enabled"]) ? "aktiv" : undefined,
        "Knoten mit öffentlicher IP":
          pools
            .filter((a) => bool(a["enableNodePublicIP"]))
            .map((a) => str(a["name"]))
            .join(", ") || undefined,
        Hinweis:
          "Kubernetes-Ingress-Objekte und Services werden nicht über ARM gelesen; sichtbar sind die Load Balancer/Public IPs der Node-Resource-Group.",
      });
      const outboundType = str(net["outboundType"]) ?? "loadBalancer";
      const lbProfile = obj(net["loadBalancerProfile"]);
      const natProfile = obj(net["natGatewayProfile"]);
      const effective = [
        ...arr(lbProfile["effectiveOutboundIPs"]),
        ...arr(natProfile["effectiveOutboundIPs"]),
      ].flatMap((x) => ids(obj(x)["id"]));
      hints.aksOutboundIpIds = effective;
      for (const id of effective) link(id, "Ausgangs-IP", "egress");
      switch (outboundType.toLowerCase()) {
        case "loadbalancer":
          egressMode = "load-balancer";
          break;
        case "managednatgateway":
        case "userassignednatgateway":
          egressMode = "nat-gateway";
          break;
        case "userdefinedrouting":
          egressMode = "udr";
          break;
        case "none":
        case "block":
          egressMode = "none";
          egressExtra = `Outbound-Typ ${outboundType}`;
          break;
        default:
          egressMode = "unknown";
      }
      egressSubnets = ids(
        ...pools.flatMap((a) => [
          a["vnetSubnetID"] ?? a["vnetSubnetId"],
          a["podSubnetID"] ?? a["podSubnetId"],
        ]),
      );
      egressDetails = details({
        "Outbound-Typ": outboundType,
        "Netzwerk-Plugin": [str(net["networkPlugin"]), str(net["networkPluginMode"])]
          .filter(Boolean)
          .join(" / "),
        "Network Policy": str(net["networkPolicy"]) ?? "keine",
        Dataplane: str(net["networkDataplane"]),
        "Pod-CIDR": strings(net["podCidrs"]).join(", ") || str(net["podCidr"]),
        "Service-CIDR": strings(net["serviceCidrs"]).join(", ") || str(net["serviceCidr"]),
        "DNS-Service-IP": str(net["dnsServiceIP"]),
        "Load-Balancer-SKU": str(net["loadBalancerSku"]),
        "Verwaltete Ausgangs-IPs": num(obj(lbProfile["managedOutboundIPs"])["count"]),
        "Static Egress Gateway": bool(obj(net["staticEgressGatewayProfile"])["enabled"]),
      });
      break;
    }
    case "microsoft.containerinstance/containergroups": {
      const ip = obj(p["ipAddress"]);
      const kind = str(ip["type"]);
      const groupSubnets = ids(...arr(p["subnetIds"]).map((s) => obj(s)["id"]));
      ingressMode = !kind ? "none" : kind.toLowerCase() === "public" ? "internet" : "vnet";
      ingressRules = [];
      ingressIps = strings([ip["ip"]]);
      ingressDetails = details({
        "IP-Typ": kind,
        Ports: arr(ip["ports"])
          .map((x) => `${num(obj(x)["port"]) ?? "?"}/${str(obj(x)["protocol"]) ?? "TCP"}`)
          .join(", "),
        FQDN: str(ip["fqdn"]),
      });
      egressSubnets = groupSubnets;
      egressMode = groupSubnets.length ? "vnet" : "azure-default";
      break;
    }

    // --- Databases ----------------------------------------------------------------------------------------
    case "microsoft.dbforpostgresql/flexibleservers":
    case "microsoft.dbformysql/flexibleservers": {
      const network = obj(p["network"]);
      const zone = normalizeId(str(network["privateDnsZoneArmResourceId"]));
      if (zone) link(zone, "Private DNS Zone", "ingress");
      if (rules && rules.status !== "not-accessible") ingressRules = armRangeRules(rules.firewallRules);
      ingressDetails = details({
        Zugriffsmodell: subnets.length
          ? "Private Access (VNet-Integration / delegiertes Subnet)"
          : e.privateEndpointIds.length
            ? "Public Access + Private Endpoint"
            : "Public Access",
        "Azure-Dienste erlaubt (0.0.0.0)":
          ingressRules.some((r) => r.source.startsWith("AzureServices")) || undefined,
        "Hohe Verfügbarkeit": str(obj(p["highAvailability"])["mode"]),
      });
      if (subnets.length) {
        egressMode = "vnet";
        egressSubnets = [...subnets];
      }
      break;
    }
    case "microsoft.sql/servers": {
      if (rules && rules.status !== "not-accessible") {
        ingressRules = [
          ...armRangeRules(rules.firewallRules),
          ...rules.virtualNetworkRules.flatMap((r) => {
            const id = normalizeId(str(obj(obj(r)["properties"])["virtualNetworkSubnetId"]));
            return id ? [{ name: str(obj(r)["name"]), source: id, action: "Allow" as const }] : [];
          }),
        ];
      }
      const restrict = str(p["restrictOutboundNetworkAccess"]);
      ingressDetails = details({
        "Mindest-TLS": str(p["minimalTlsVersion"]),
        "Azure-Dienste erlaubt (0.0.0.0)":
          ingressRules.some((r) => r.source.startsWith("AzureServices")) || undefined,
      });
      if (restrict?.toLowerCase() === "enabled") {
        egressMode = "azure-default";
        egressExtra = "Ausgehender Zugriff eingeschränkt (Outbound-Firewall-Regeln)";
      }
      egressDetails = details({ "Outbound-Einschränkung": restrict });
      break;
    }
    case "microsoft.sql/managedinstances":
      ingressDetails = details({
        "Öffentlicher Datenendpunkt (Port 3342)": bool(p["publicDataEndpointEnabled"]),
        Verbindungstyp: str(p["proxyOverride"]),
        "Mindest-TLS": str(p["minimalTlsVersion"]),
      });
      break;
    case "microsoft.cache/redis":
      if (rules && rules.status !== "not-accessible") ingressRules = armRangeRules(rules.firewallRules);
      ingressDetails = details({
        "Nicht-TLS-Port 6379": bool(p["enableNonSslPort"]),
        "Mindest-TLS": str(p["minimumTlsVersion"]),
      });
      break;

    // --- Integration ---------------------------------------------------------------------------------------
    case "microsoft.apimanagement/service": {
      const vnetType = str(p["virtualNetworkType"]) ?? "None";
      ingressMode =
        e.publicNetworkAccess === "Disabled"
          ? e.privateEndpointIds.length
            ? "private-endpoint"
            : "vnet"
          : vnetType.toLowerCase() === "internal"
            ? "vnet"
            : "internet";
      ingressIps = [...strings(p["publicIPAddresses"]), ...strings(p["privateIPAddresses"])];
      const pip = normalizeId(str(p["publicIpAddressId"]));
      if (pip) link(pip, "Public IP", "ingress");
      ingressExtra = "IP-Filter über APIM-Policies (ip-filter) sind nicht per ARM sichtbar";
      ingressDetails = details({
        "VNet-Typ": vnetType,
        "Gateway-URL": str(p["gatewayUrl"]),
        Entwicklerportal: str(p["developerPortalUrl"]),
        "Weitere Regionen": arr(p["additionalLocations"]).length || undefined,
      });
      if (vnetType.toLowerCase() !== "none" && subnets.length) {
        egressMode = "vnet";
        egressSubnets = [...subnets];
      }
      egressIps = strings(p["outboundPublicIPAddresses"]).length
        ? strings(p["outboundPublicIPAddresses"])
        : egressIps;
      egressDetails = details({ "NAT Gateway": str(p["natGatewayState"]) });
      break;
    }
    case "microsoft.servicebus/namespaces":
    case "microsoft.eventhub/namespaces": {
      const set = obj(obj(rules?.extra?.["networkRuleSet"]?.[0])["properties"]);
      if (Object.keys(set).length) {
        ingressRules = [
          ...arr(set["ipRules"]).flatMap((r) =>
            str(obj(r)["ipMask"])
              ? [{ source: str(obj(r)["ipMask"])!, action: ruleAction(obj(r)["action"]) }]
              : [],
          ),
          ...arr(set["virtualNetworkRules"]).flatMap((r) => {
            const id = normalizeId(str(obj(obj(r)["subnet"])["id"]));
            return id ? [{ source: id, action: "Allow" as const, name: "VNet-Regel" }] : [];
          }),
        ];
        ingressDetails = details({
          Standardaktion: str(set["defaultAction"]),
          "Vertrauenswürdige Microsoft-Dienste": bool(set["trustedServiceAccessEnabled"]),
        });
      }
      break;
    }
    case "microsoft.devices/iothubs": {
      const set = obj(p["networkRuleSets"]);
      ingressRules = arr(set["ipRules"]).flatMap((r) =>
        str(obj(r)["ipMask"])
          ? [
              {
                name: str(obj(r)["filterName"]),
                source: str(obj(r)["ipMask"])!,
                action: ruleAction(obj(r)["action"]),
              },
            ]
          : [],
      );
      egressMode = "azure-default";
      egressExtra = "Nachrichten-Routing zu Endpunkten über den Plattform-Ausgang";
      break;
    }
    case "microsoft.eventgrid/topics":
    case "microsoft.eventgrid/domains":
      egressMode = "azure-default";
      egressExtra = "Zustellung an Webhooks/Handler über den Plattform-Ausgang";
      break;

    // --- AI / Analytics -------------------------------------------------------------------------------------
    case "microsoft.cognitiveservices/accounts": {
      const restrict = bool(p["restrictOutboundNetworkAccess"]) === true;
      if (restrict) allowedTargets = strings(p["allowedFqdnList"]);
      ingressDetails = details({
        "Eigene Subdomain": str(p["customSubDomainName"]),
        "Lokale Authentifizierung aus": bool(p["disableLocalAuth"]),
      });
      egressDetails = details({ "Ausgang eingeschränkt (FQDN-Liste)": restrict });
      break;
    }
    case "microsoft.machinelearningservices/workspaces": {
      const managed = obj(p["managedNetwork"]);
      const isolation = str(managed["isolationMode"]) ?? "Disabled";
      const outRules = Object.entries(obj(managed["outboundRules"])).map(([name, r]) => {
        const o = obj(r);
        const dest = o["destination"];
        const target =
          typeof dest === "string"
            ? dest
            : (str(obj(dest)["serviceResourceId"]) ?? str(obj(dest)["serviceTag"]) ?? name);
        return `${name}: ${target}`;
      });
      ingressRules = [
        ...ingressRules,
        ...strings(p["ipAllowlist"]).map((ip) => ({ source: ip, action: "Allow" as const })),
      ];
      if (isolation.toLowerCase() === "disabled") {
        egressMode = "azure-default";
        egressExtra = "kein Managed VNet – Compute im eigenen VNet bestimmt den Ausgang";
      } else {
        egressMode = "managed-vnet";
        if (isolation.toLowerCase() === "allowonlyapprovedoutbound") allowedTargets = outRules;
      }
      egressDetails = details({
        "Managed-Network-Isolation": isolation,
        "Outbound-Regeln": outRules.length || undefined,
      });
      break;
    }
    case "microsoft.datafactory/factories": {
      const managed = rules?.extra?.["managedVirtualNetworks"] ?? [];
      const runtimes = (rules?.extra?.["integrationRuntimes"] ?? []).map((r) => {
        const o = obj(r);
        return `${str(o["name"]) ?? "?"} (${str(obj(o["properties"])["type"]) ?? "?"})`;
      });
      egressMode = managed.length ? "managed-vnet" : "azure-default";
      if (runtimes.some((r) => r.includes("SelfHosted")))
        egressExtra = "Self-hosted Integration Runtime: Ausgang über deren Netzwerk";
      egressDetails = details({
        "Managed VNet": managed.length ? "ja" : rules ? "nein" : undefined,
        "Integration Runtimes": runtimes.join(", ") || undefined,
      });
      break;
    }
    case "microsoft.synapse/workspaces": {
      if (rules && rules.status !== "not-accessible") ingressRules = armRangeRules(rules.firewallRules);
      const settings = obj(p["managedVirtualNetworkSettings"]);
      const managed = str(p["managedVirtualNetwork"])?.toLowerCase() === "default";
      egressMode = managed ? "managed-vnet" : "azure-default";
      if (bool(settings["preventDataExfiltration"]))
        allowedTargets = strings(settings["allowedAadTenantIdsForLinking"]).map((t) => `Tenant ${t}`);
      egressDetails = details({
        "Managed VNet": managed,
        "Schutz vor Datenexfiltration": bool(settings["preventDataExfiltration"]),
      });
      break;
    }
    case "microsoft.databricks/workspaces": {
      const params = obj(p["parameters"]);
      const noPublicIp = bool(obj(params["enableNoPublicIp"])["value"]);
      ingressDetails = details({
        "Erforderliche NSG-Regeln": str(p["requiredNsgRules"]),
        "Secure Cluster Connectivity (keine öffentlichen IPs)": noPublicIp,
      });
      egressMode = subnets.length ? "vnet" : "managed-vnet";
      egressDetails = details({
        "NAT Gateway": str(obj(params["natGatewayName"])["value"]),
        "Ausgangs-IP-Name": str(obj(params["publicIpName"])["value"]),
      });
      break;
    }
    case "microsoft.kusto/clusters": {
      const vnet = obj(p["virtualNetworkConfiguration"]);
      const subnet = ids(vnet["subnetId"]);
      ingressRules = strings(p["allowedIpRangeList"]).map((r) => ({ source: r, action: "Allow" as const }));
      if (subnet.length) {
        egressMode = "vnet";
        egressSubnets = subnet;
      }
      const restrict = str(p["restrictOutboundNetworkAccess"])?.toLowerCase() === "enabled";
      if (restrict) allowedTargets = strings(p["allowedFqdnList"]);
      ingressDetails = details({ "Öffentlicher IP-Typ": str(p["publicIPType"]) });
      egressDetails = details({ "Ausgang eingeschränkt": restrict });
      break;
    }
    case "microsoft.fabric/capacities":
    case "microsoft.powerbidedicated/capacities":
      ingressMode = "unknown";
      egressMode = "unknown";
      ingressExtra =
        "Fabric/Power BI: Netzwerkzugriff wird im Tenant (Admin-Portal: Private Link, „Block Public Internet Access“) bzw. je Workspace (Workspace Private Link, Zugriffsschutz) gesteuert – nicht über ARM lesbar";
      egressExtra = "Ausgehender Zugriffsschutz je Fabric-Workspace – nicht über ARM lesbar";
      ingressDetails = details({
        Status: str(p["state"]),
        Administratoren: strings(obj(p["administration"])["members"]).length || undefined,
      });
      break;
    case "microsoft.fabric/privatelinkservicesforfabric":
    case "microsoft.powerbi/privatelinkservicesforpowerbi":
      ingressMode = e.privateEndpointIds.length ? "private-endpoint" : "unknown";
      ingressExtra =
        "Private-Link-Anker für den ganzen Tenant; ob öffentlicher Zugriff zusätzlich gesperrt ist, steht im Fabric-Admin-Portal";
      ingressDetails = details({ Tenant: str(p["tenantId"]) });
      break;

    // --- AVD ------------------------------------------------------------------------------------------------
    case "microsoft.desktopvirtualization/hostpools": {
      const access = str(p["publicNetworkAccess"]) ?? "Enabled";
      const hosts = (rules?.extra?.["sessionHosts"] ?? []).flatMap((h) =>
        ids(obj(obj(h)["properties"])["resourceId"]),
      );
      hints.sessionHostVmIds = hosts;
      for (const vm of hosts) link(vm, "Session Host", "egress");
      const clientsPublic = access === "Enabled" || access === "EnabledForClientsOnly";
      const hostsPublic = access === "Enabled" || access === "EnabledForSessionHostsOnly";
      ingressMode = clientsPublic ? "internet" : e.privateEndpointIds.length ? "private-endpoint" : "none";
      ingressRules = [];
      ingressExtra = "Reverse Connect: Session Hosts brauchen keine eingehenden Ports";
      const shortpath = (key: string) => str(p[key]);
      ingressDetails = details({
        "Öffentlicher Zugriff": access,
        "Clients über Internet": clientsPublic,
        "Session Hosts über Internet": hostsPublic,
        "Host-Pool-Typ": str(p["hostPoolType"]),
        Lastverteilung: str(p["loadBalancerType"]),
        "Start VM on Connect": bool(p["startVMOnConnect"]),
        "RDP Shortpath (verwaltete Netze)": shortpath("managedPrivateUDP"),
        "RDP Shortpath (direkt)": shortpath("directUDP"),
        "RDP Shortpath (öffentlich, STUN)": shortpath("publicUDP"),
        "RDP Shortpath (TURN-Relay)": shortpath("relayUDP"),
        "Eigene RDP-Eigenschaften": str(p["customRdpProperty"]),
        "Session Hosts": rules?.extra ? hosts.length : undefined,
      });
      egressMode = hosts.length ? "vnet" : "unknown";
      egressExtra = hostsPublic
        ? "Session Hosts brauchen Ausgang zu WindowsVirtualDesktop, AzureFrontDoor.Frontend, AzureMonitor (Service Tags)"
        : "Session Hosts erreichen den Dienst über Private Endpoint (connection)";
      egressDetails = details({
        "Erforderliche Service Tags": "WindowsVirtualDesktop, AzureFrontDoor.Frontend, AzureMonitor",
        "Erforderliche Plattform-IPs": "169.254.169.254, 168.63.129.16",
      });
      break;
    }
    case "microsoft.desktopvirtualization/workspaces": {
      hints.applicationGroupIds = ids(...arr(p["applicationGroupReferences"]));
      for (const g of hints.applicationGroupIds) link(g, "Application Group", "other");
      ingressDetails = details({ "Öffentlicher Zugriff (Feed)": str(p["publicNetworkAccess"]) });
      break;
    }

    // --- Edge / Monitoring / Others ----------------------------------------------------------------------------
    case "microsoft.cdn/profiles":
      ingressMode = "internet";
      ingressRules = [];
      ingressExtra = "Globaler Edge-Einstiegspunkt; Schutz über WAF-Policy und Origin-Absicherung";
      egressMode = "azure-default";
      egressExtra = "zu den Origins über Internet oder Private Link (Premium)";
      ingressDetails = details({ SKU: e.sku, "Origin-Timeout (s)": num(p["originResponseTimeoutSeconds"]) });
      break;
    case "microsoft.dashboard/grafana": {
      const deterministic = str(p["deterministicOutboundIP"])?.toLowerCase() === "enabled";
      egressIps = strings(p["outboundIPs"]);
      egressDetails = details({ "Feste Ausgangs-IPs": deterministic });
      break;
    }
    case "microsoft.batch/batchaccounts": {
      const profile = obj(p["networkProfile"]);
      const accountRules = (scope: string, x: unknown) =>
        arr(obj(x)["ipRules"]).flatMap((r) =>
          str(obj(r)["value"])
            ? [{ source: str(obj(r)["value"])!, action: ruleAction(obj(r)["action"]), scope }]
            : [],
        );
      ingressRules = [
        ...accountRules("Konto", profile["accountAccess"]),
        ...accountRules("Knotenverwaltung", profile["nodeManagementAccess"]),
      ];
      egressMode = "unknown";
      egressExtra = "Ausgang hängt von der Netzwerkkonfiguration der Pools ab";
      break;
    }
    case "microsoft.insights/components":
    case "microsoft.operationalinsights/workspaces": {
      hints.privateLinkScopeIds = arr(p["privateLinkScopedResources"]).flatMap((r) => ids(obj(r)["scopeId"]));
      for (const s of hints.privateLinkScopeIds) link(s, "Azure Monitor Private Link Scope", "ingress");
      ingressDetails = details({
        "Öffentliche Datenaufnahme": str(p["publicNetworkAccessForIngestion"]),
        "Öffentliche Abfragen": str(p["publicNetworkAccessForQuery"]),
      });
      const workspace = normalizeId(str(p["WorkspaceResourceId"]) ?? str(p["workspaceResourceId"]));
      if (workspace) link(workspace, "Log Analytics Workspace", "other");
      break;
    }
    case "microsoft.insights/privatelinkscopes": {
      const modes = obj(p["accessModeSettings"]);
      ingressDetails = details({
        "Zugriffsmodus Datenaufnahme": str(modes["ingestionAccessMode"]),
        "Zugriffsmodus Abfragen": str(modes["queryAccessMode"]),
      });
      break;
    }
    case "microsoft.storage/storageaccounts": {
      const acl = obj(p["networkAcls"]);
      ingressRules = [
        ...arr(acl["ipRules"]).flatMap((r) =>
          str(obj(r)["value"])
            ? [{ source: str(obj(r)["value"])!, action: ruleAction(obj(r)["action"]) }]
            : [],
        ),
        ...arr(acl["virtualNetworkRules"]).flatMap((r) =>
          ids(obj(r)["id"]).map((id) => ({
            source: id,
            action: ruleAction(obj(r)["action"]),
            name: "VNet-Regel",
          })),
        ),
        ...arr(acl["resourceAccessRules"]).flatMap((r) =>
          ids(obj(r)["resourceId"]).map((id) => ({
            source: id,
            action: "Allow" as const,
            name: "Instanzregel",
          })),
        ),
      ];
      ingressDetails = details({
        "Anonymer Blob-Zugriff erlaubt": bool(p["allowBlobPublicAccess"]),
        "Shared-Key-Zugriff": bool(p["allowSharedKeyAccess"]),
        "Nur HTTPS": bool(p["supportsHttpsTrafficOnly"]),
        SFTP: bool(p["isSftpEnabled"]),
        Ausnahmen: str(acl["bypass"]),
      });
      break;
    }
    case "microsoft.containerregistry/registries":
      ingressDetails = details({
        "Anonymer Pull": bool(p["anonymousPullEnabled"]),
        "Dedizierte Datenendpunkte": bool(p["dataEndpointEnabled"]),
        "Vertrauenswürdige Dienste": str(p["networkRuleBypassOptions"]),
        Exportrichtlinie: str(obj(obj(p["policies"])["exportPolicy"])["status"]),
      });
      break;
  }

  const ingress: PaasIngress = {
    mode: ingressMode,
    summary: ingressSummary(ingressMode, e, ingressExtra),
    rules: ingressRules,
    ips: [...new Set(ingressIps)],
    details: ingressDetails,
  };
  const egress: PaasEgress = {
    mode: egressMode,
    summary: `${EGRESS_LABEL[egressMode]}${egressExtra ? ` · ${egressExtra}` : ""}`,
    subnetIds: [...new Set(egressSubnets)],
    outboundIps: [...new Set(egressIps)],
    ...(allowedTargets ? { allowedTargets } : {}),
    details: egressDetails,
  };
  return { ingress, egress, links, hints };
}

/** Recomputes the ingress summary after linking changed the mode. */
export function setIngressMode(e: PaasServiceEntity, mode: PaasIngressMode, extra?: string): void {
  if (!e.ingress) return;
  e.ingress.mode = mode;
  e.ingress.summary = ingressSummary(mode, e, extra);
}

export function setEgress(
  e: PaasServiceEntity,
  mode: PaasEgressMode,
  subnetIds: string[],
  extra?: string,
): void {
  if (!e.egress) return;
  e.egress.mode = mode;
  e.egress.subnetIds = [...new Set(subnetIds)];
  e.egress.summary = `${EGRESS_LABEL[mode]}${extra ? ` · ${extra}` : ""}`;
}
