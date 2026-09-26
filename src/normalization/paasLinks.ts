import type { RawResource } from "../models/discovery.js";
import type { NormalizedInventory, PaasServiceEntity } from "../models/network.js";
import { normalizeId } from "../utils/ids.js";
import { obj, str } from "./access.js";
import { LINK_HINTS, setEgress, setIngressMode } from "./paasNetwork.js";

const addLink = (
  e: PaasServiceEntity,
  id: string,
  label: string,
  direction: "ingress" | "egress" | "other",
) => {
  e.links ??= [];
  if (!e.links.some((l) => l.id === id && l.label === label)) e.links.push({ id, label, direction });
};

/**
 * Resolves the cross-resource parts of the PaaS ingress/egress profiles once the whole inventory is
 * normalized: container apps inherit their environment's network, AKS clusters get the load balancers
 * and public IPs of their node resource group, host pools their session host subnets, App Service apps
 * in an App Service Environment its network, Front Door profiles the host names of their endpoints.
 */
export function linkPaasNetwork(inv: NormalizedInventory, auxRows: RawResource[]): void {
  const services = new Map(inv.paasServices.map((s) => [s.id, s]));
  const publicIps = new Map(inv.publicIps.map((p) => [p.id, p]));
  const ipOf = (id: string) => publicIps.get(id)?.ipAddress;
  const subnetsById = new Map(inv.subnets.map((s) => [s.id, s]));

  // Delegated subnets: the platform records the user in serviceAssociationLinks/resourceNavigationLinks.
  for (const subnet of inv.subnets) {
    for (const l of subnet.serviceLinks ?? []) {
      const service = l.linkId ? services.get(l.linkId) : undefined;
      if (!service) continue;
      if (!service.vnetIntegration.subnetIds.includes(subnet.id)) {
        service.vnetIntegration = {
          ...service.vnetIntegration,
          subnetIds: [...service.vnetIntegration.subnetIds, subnet.id],
          mode: service.azureType === "microsoft.web/serverfarms" ? "integration" : "injection",
        };
      }
      addLink(
        service,
        subnet.id,
        `delegiertes Subnet (${l.linkedResourceType ?? "Service Association Link"})`,
        "egress",
      );
      if (service.egress && !service.egress.subnetIds.includes(subnet.id)) {
        const plan = service.azureType === "microsoft.web/serverfarms";
        setEgress(
          service,
          plan
            ? "vnet-partial"
            : service.egress.mode === "azure-default" || service.egress.mode === "unknown"
              ? "vnet"
              : service.egress.mode,
          [...service.egress.subnetIds, subnet.id],
          plan
            ? "Integrations-Subnet der Apps; Internet-Verkehr nur mit „Route All“ je App"
            : "über das delegierte Subnet",
        );
      }
    }
  }

  // Application Gateway for Containers: associations (subnet) and frontends (FQDN) are child resources.
  for (const r of auxRows) {
    const type = r.type.toLowerCase();
    if (!type.startsWith("microsoft.servicenetworking/trafficcontrollers/")) continue;
    const parent = normalizeId(r.id)?.replace(/\/(associations|frontends)\/[^/]+$/, "");
    const agc = parent ? services.get(parent) : undefined;
    if (!agc) continue;
    const props = obj(r.properties);
    if (type.endsWith("/associations")) {
      const subnet = normalizeId(str(obj(props["subnet"])["id"]));
      if (subnet && !agc.vnetIntegration.subnetIds.includes(subnet)) {
        agc.vnetIntegration = { subnetIds: [...agc.vnetIntegration.subnetIds, subnet], mode: "injection" };
        if (agc.egress)
          setEgress(
            agc,
            "vnet",
            [...agc.egress.subnetIds, subnet],
            "zu den Pods über das zugeordnete Subnet",
          );
      }
    } else {
      const fqdn = str(props["fqdn"])?.toLowerCase();
      if (fqdn && !agc.endpoints.includes(fqdn)) agc.endpoints.push(fqdn);
    }
  }

  for (const e of inv.paasServices) {
    const hints = LINK_HINTS.get(e);
    if (!hints) continue;

    // App Service app → plan; classic VNet integration shows up only as config/web vnetName.
    if (hints.serverFarmId) {
      const plan = services.get(hints.serverFarmId);
      if (plan) {
        addLink(plan, e.id, "App", "other");
        const planSubnets = plan.vnetIntegration.subnetIds;
        if (e.vnetIntegration.subnetIds.length === 0 && hints.webVnetName && planSubnets.length && e.egress) {
          e.vnetIntegration = {
            subnetIds: [...planSubnets],
            mode: "integration",
            routeAll: hints.webRouteAll,
          };
          setEgress(
            e,
            hints.webRouteAll ? "vnet" : "vnet-partial",
            planSubnets,
            hints.webRouteAll
              ? "über das Integrations-Subnet des Plans"
              : "nur private Ziele über das Integrations-Subnet des Plans",
          );
          e.egress.details["VNet-Integration"] = `ja (${hints.webVnetName})`;
        }
      }
    }

    // AKS virtual nodes (ACI connector): subnet by name in the node VNet.
    if (hints.aciSubnetName && e.egress) {
      const vnets = new Set(
        e.egress.subnetIds.flatMap((id) => (subnetsById.get(id) ? [subnetsById.get(id)!.vnetId] : [])),
      );
      const aci = inv.subnets.find(
        (sn) => vnets.has(sn.vnetId) && sn.name.toLowerCase() === hints.aciSubnetName!.toLowerCase(),
      );
      if (aci) {
        e.egress.subnetIds = [...new Set([...e.egress.subnetIds, aci.id])];
        addLink(e, aci.id, "Virtual Nodes (ACI)", "egress");
      }
    }

    // Container app / job → environment.
    if (hints.environmentId) {
      const env = services.get(hints.environmentId);
      const envHints = env ? LINK_HINTS.get(env) : undefined;
      if (env) {
        e.vnetIntegration = { subnetIds: [...env.vnetIntegration.subnetIds], mode: "injection" };
        if (env.egress)
          setEgress(e, env.egress.mode, env.egress.subnetIds, "über die Container Apps Environment");
        if (env.egress)
          for (const ip of e.outboundIps)
            if (!env.egress.outboundIps.includes(ip)) env.egress.outboundIps.push(ip);
        if (e.egress) e.egress.outboundIps = [...new Set([...e.egress.outboundIps, ...e.outboundIps])];
        if (e.ingress && envHints?.environmentInternal && e.ingress.mode.startsWith("internet")) {
          // External ingress in an internal environment is reachable from the VNet only.
          e.publicNetworkAccess = "Disabled";
          setIngressMode(e, "vnet", "Environment intern: externer Ingress nur aus dem VNet erreichbar");
        }
        if (e.ingress && env.ingress?.mode === "private-endpoint" && e.ingress.mode.startsWith("internet")) {
          e.publicNetworkAccess = "Disabled";
          setIngressMode(e, "private-endpoint", "über den Private Endpoint der Environment");
        }
        addLink(
          env,
          e.id,
          e.azureType === "microsoft.app/jobs" ? "Container Apps Job" : "Container App",
          "other",
        );
      }
    }

    // AKS → node resource group load balancers and public IPs.
    if (hints.aksNodeResourceGroup !== undefined && e.ingress && e.egress) {
      const rg = hints.aksNodeResourceGroup;
      const inRg = (x: { resourceGroup?: string | undefined; subscriptionId?: string | undefined }) =>
        x.resourceGroup?.toLowerCase() === rg && x.subscriptionId === e.subscriptionId;
      const lbs = inv.loadBalancers.filter(inRg);
      const publicFrontendIps: string[] = [];
      const internalFrontendIps: string[] = [];
      let publicServices = 0;
      let internalServices = 0;
      for (const lb of lbs) {
        addLink(e, lb.id, lb.isPublic ? "Load Balancer (öffentlich)" : "Load Balancer (intern)", "ingress");
        // Frontends used by load-balancing rules are Kubernetes services of type LoadBalancer.
        const used = new Set(lb.rules.map((r) => r.frontendName?.toLowerCase()));
        for (const f of lb.frontends) {
          if (!used.has(f.name.toLowerCase())) continue;
          if (f.publicIpId) {
            const ip = ipOf(f.publicIpId);
            if (ip) publicFrontendIps.push(ip);
            publicServices++;
          } else if (f.privateIpAddress) {
            internalFrontendIps.push(f.privateIpAddress);
            internalServices++;
          }
        }
      }
      e.ingress.ips = [...new Set([...publicFrontendIps, ...internalFrontendIps])];
      e.ingress.details["Öffentliche LB-Frontends mit Regeln"] = String(publicServices);
      e.ingress.details["Interne LB-Frontends mit Regeln"] = String(internalServices);
      const agic = hints.aksAppGatewayId
        ? inv.applicationGateways.find((g) => g.id === hints.aksAppGatewayId)
        : undefined;
      const agicPublic = agic?.frontends.some((f) => f.publicIpId) ?? false;
      const apiPrivate = e.ingress.details["API-Server privat (Private Cluster)"] === "ja";
      const apiNote = e.ingress.summary.split(" · ").find((x) => x.startsWith("API-Server"));
      const mode =
        publicServices > 0 || agicPublic ? "internet" : internalServices > 0 || agic ? "vnet" : "none";
      setIngressMode(
        e,
        mode,
        [mode === "none" ? "keine Workload-Ingress-Frontends gefunden" : "Workloads", apiNote]
          .filter(Boolean)
          .join(" · "),
      );
      if (!apiPrivate && e.firewall.defaultAction !== "Deny")
        e.ingress.details["Hinweis API-Server"] = "öffentlich ohne IP-Einschränkung";
      // Outbound IPs of the load balancer / NAT gateway.
      e.egress.outboundIps = [
        ...new Set([
          ...e.egress.outboundIps,
          ...(hints.aksOutboundIpIds ?? []).flatMap((id) => (ipOf(id) ? [ipOf(id)!] : [])),
        ]),
      ];
      // Managed VNet (kubenet without custom subnet): the VNet in the node resource group.
      if (e.egress.subnetIds.length === 0) {
        const managed = inv.subnets.filter((s) => inRg(s));
        if (managed.length) {
          e.egress.subnetIds = managed.map((s) => s.id);
          e.egress.details["VNet"] = "von AKS verwaltet (Node-Resource-Group)";
        }
      }
      if (e.vnetIntegration.subnetIds.length === 0 && e.egress.subnetIds.length)
        e.vnetIntegration = { subnetIds: [...e.egress.subnetIds], mode: "injection" };
    }

    // App Service app in an App Service Environment.
    if (hints.aseId) {
      const ase = services.get(hints.aseId);
      if (ase?.ingress && ase.egress && e.ingress && e.egress) {
        if (ase.ingress.mode === "vnet" && e.ingress.mode.startsWith("internet")) {
          e.publicNetworkAccess = "Disabled";
          setIngressMode(e, "vnet", "über den internen Load Balancer der App Service Environment");
        }
        setEgress(e, "vnet", ase.egress.subnetIds, "über die App Service Environment");
        e.egress.outboundIps = [...ase.egress.outboundIps];
        e.vnetIntegration = { subnetIds: [...ase.vnetIntegration.subnetIds], mode: "injection" };
      }
    }

    // AVD host pool → session host VMs → subnets.
    if (hints.sessionHostVmIds?.length && e.egress) {
      const vmIds = new Set(hints.sessionHostVmIds);
      const nicIds = new Set(inv.virtualMachines.filter((v) => vmIds.has(v.id)).flatMap((v) => v.nicIds));
      const subnetIds = [
        ...new Set(inv.networkInterfaces.filter((n) => nicIds.has(n.id)).flatMap((n) => n.subnetIds)),
      ];
      e.egress.subnetIds = subnetIds;
      e.egress.details["Session-Host-Subnets"] = String(subnetIds.length);
    }

    // AVD workspace → application groups → host pools.
    if (hints.applicationGroupIds?.length) {
      for (const g of auxRows) {
        const id = normalizeId(g.id);
        if (!id || !hints.applicationGroupIds.includes(id)) continue;
        const pool = normalizeId(str(obj(g.properties)["hostPoolArmPath"]));
        const hostPool = pool ? services.get(pool) : undefined;
        if (hostPool) {
          addLink(e, hostPool.id, "Host Pool", "other");
          addLink(hostPool, e.id, "AVD Workspace", "other");
        }
      }
    }
  }

  // Fabric / Power BI: network access is a tenant setting. Without a tenant Private Link the service is
  // reachable from the Internet (Microsoft default; protected by Entra ID / Conditional Access only).
  const privateLinks = inv.paasServices.filter(
    (s) =>
      s.azureType === "microsoft.fabric/privatelinkservicesforfabric" ||
      s.azureType === "microsoft.powerbi/privatelinkservicesforpowerbi",
  );
  for (const e of inv.paasServices) {
    if (
      e.azureType !== "microsoft.fabric/capacities" &&
      e.azureType !== "microsoft.powerbidedicated/capacities"
    )
      continue;
    if (privateLinks.length === 0) {
      e.publicNetworkAccess = "Enabled";
      e.firewall = { defaultAction: "Allow", ipRules: [], subnetIds: [], source: "arg" };
      setIngressMode(
        e,
        "internet",
        "kein Tenant-Private-Link im Inventar: Zugriff über das öffentliche Internet (Schutz nur über Entra ID / Conditional Access)",
      );
    } else {
      const endpoints = privateLinks.reduce((n, p) => n + p.privateEndpointIds.length, 0);
      for (const pl of privateLinks) addLink(e, pl.id, "Tenant-Private-Link", "ingress");
      setIngressMode(
        e,
        "unknown",
        `Tenant-Private-Link vorhanden (${endpoints} Private Endpoint(s)); ob „Block Public Internet Access“ aktiv ist, zeigt nur das Fabric-Admin-Portal`,
      );
    }
  }

  // Front Door: endpoint host names (child resources) complete the profile.
  for (const r of auxRows) {
    if (r.type.toLowerCase() !== "microsoft.cdn/profiles/afdendpoints") continue;
    const profileId = normalizeId(r.id)?.replace(/\/afdendpoints\/[^/]+$/, "");
    const profile = profileId ? services.get(profileId) : undefined;
    const host = str(obj(r.properties)["hostName"]);
    if (profile && host && !profile.endpoints.includes(host.toLowerCase()))
      profile.endpoints.push(host.toLowerCase());
  }
}
