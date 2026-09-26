import { cidrContains } from "../addressing/ip.js";
import type { NormalizedInventory, PrivateEndpointEntity } from "../models/network.js";
import { PRIVATE_LINK_ZONES } from "../models/paasCatalog.js";
import { lastSegment } from "../utils/ids.js";
import { finding, type Finding } from "./types.js";

/** Azure-provided DNS (virtual public IP of the platform resolver). */
export const AZURE_DNS_IP = "168.63.129.16";

export interface DnsServerTarget {
  ip: string;
  /** What the configured DNS server IP belongs to. */
  kind: "azureDns" | "resolverInbound" | "firewall" | "vnet" | "external";
  resourceId?: string | undefined;
  name?: string | undefined;
  /** VNet the server lives in (its Private DNS zone links apply). */
  vnetId?: string | undefined;
}

export interface VnetDnsSetting {
  vnetId: string;
  vnet: string;
  mode: "azure" | "custom";
  servers: DnsServerTarget[];
  /** VNets whose Private DNS zone links answer this VNet's queries. */
  resolvingVnetIds: string[];
  /** False when at least one server is outside the discovered VNets (e.g. on-premises). */
  verifiable: boolean;
  linkedZones: string[];
  rulesets: string[];
}

export type PeDnsStatus =
  | "ok"
  | "missing-zone"
  | "missing-record"
  | "not-linked"
  | "unverifiable"
  | "unknown-zone"
  /** Connection not approved (pending, rejected, disconnected): no DNS check. */
  | "inactive";

export interface PeDnsCheck {
  privateEndpointId: string;
  privateEndpoint: string;
  vnetId?: string | undefined;
  targetId: string;
  target: string;
  groupId: string;
  ips: string[];
  expectedZones: string[];
  /** Zones with the expected name. */
  zoneIds: string[];
  /** Zones that hold an A record with the endpoint's IP. */
  recordZoneIds: string[];
  /** Record zones linked to a VNet whose DNS resolution applies (the working zones). */
  linkedZoneIds: string[];
  /** VNets whose Private DNS zone links apply to the endpoint's VNet (resolver/hub VNets). */
  resolvingVnetIds: string[];
  status: PeDnsStatus;
  detail: string;
}

export interface ZoneSummary {
  id: string;
  name: string;
  subscriptionId?: string | undefined;
  resourceGroup?: string | undefined;
  linkedVnetIds: string[];
  registrationVnetIds: string[];
  records: number;
  aRecords: number;
  /** Number of zones with the same name (split-horizon risk when > 1). */
  sameNameZones: number;
}

export interface ResolverSummary {
  id: string;
  name: string;
  vnetId?: string | undefined;
  inboundIps: string[];
  outboundEndpoints: string[];
  /** VNets whose DNS servers point at an inbound endpoint. */
  usedByVnetIds: string[];
}

export interface RulesetSummary {
  id: string;
  name: string;
  linkedVnetIds: string[];
  outboundEndpoints: string[];
  rules: { name: string; domain: string; targets: string[]; enabled: boolean }[];
}

export interface DnsAssessment {
  vnets: VnetDnsSetting[];
  zones: ZoneSummary[];
  resolvers: ResolverSummary[];
  rulesets: RulesetSummary[];
  privateEndpoints: PeDnsCheck[];
  findings: Finding[];
}

const vnetOfSubnet = (subnetId: string | undefined) => subnetId?.split("/subnets/")[0];
const trimDot = (s: string) => s.replace(/\.$/, "").toLowerCase();

/** Expected Private DNS zones of a private endpoint connection (group ID table, else FQDN). */
export function expectedZonesFor(groupId: string, fqdns: string[]): string[] {
  const table = PRIVATE_LINK_ZONES[groupId.toLowerCase()];
  if (table) return table;
  const derived = fqdns.flatMap((f) => {
    const labels = trimDot(f).split(".");
    return labels.length > 2 ? [`privatelink.${labels.slice(1).join(".")}`] : [];
  });
  return [...new Set(derived)];
}

function zoneMatches(pattern: string, zone: string): boolean {
  if (!pattern.includes("{region}")) return pattern === zone;
  const re = new RegExp(`^${pattern.replace(/\./g, "\\.").replace("{region}", "[a-z0-9-]+")}$`);
  return re.test(zone);
}

export function assessDns(inv: NormalizedInventory): DnsAssessment {
  const findings: Finding[] = [];
  const vnetName = new Map(inv.vnets.map((v) => [v.id, v.name]));
  const subnets = inv.subnets.map((s) => ({ s, prefixes: [...s.prefixes.ipv4, ...s.prefixes.ipv6] }));
  const vnetOfIp = (ip: string): string | undefined =>
    subnets.find((x) => x.prefixes.some((p) => cidrContains(p, ip)))?.s.vnetId ??
    inv.vnets.find((v) => [...v.addressSpace.ipv4, ...v.addressSpace.ipv6].some((p) => cidrContains(p, ip)))
      ?.id;

  const resolvers = inv.dnsResolvers.filter((d) => d.kind === "resolver");
  const inbound = inv.dnsResolvers.filter((d) => d.kind === "inboundEndpoint");
  const outbound = inv.dnsResolvers.filter((d) => d.kind === "outboundEndpoint");
  const rulesetEntities = inv.dnsResolvers.filter((d) => d.kind === "forwardingRuleset");
  const inboundByIp = new Map(inbound.flatMap((e) => e.privateIps.map((ip) => [ip, e] as const)));
  const firewallByIp = new Map(
    inv.firewalls.flatMap((f) => [...f.privateIps.ipv4, ...f.privateIps.ipv6].map((ip) => [ip, f] as const)),
  );

  // --- VNet DNS settings --------------------------------------------------------------------
  const zonesLinkedTo = new Map<string, string[]>();
  for (const z of inv.privateDnsZones)
    for (const l of z.vnetLinks)
      if (l.vnetId) zonesLinkedTo.set(l.vnetId, [...(zonesLinkedTo.get(l.vnetId) ?? []), z.name]);
  const rulesetsLinkedTo = new Map<string, string[]>();
  for (const r of rulesetEntities)
    for (const v of r.linkedVnetIds) rulesetsLinkedTo.set(v, [...(rulesetsLinkedTo.get(v) ?? []), r.name]);

  const vnets: VnetDnsSetting[] = inv.vnets.map((v) => {
    const custom = v.dnsServers.filter((ip) => ip !== AZURE_DNS_IP);
    const servers: DnsServerTarget[] = v.dnsServers.map((ip) => {
      if (ip === AZURE_DNS_IP) return { ip, kind: "azureDns", vnetId: v.id };
      const ep = inboundByIp.get(ip);
      if (ep) {
        const resolver = resolvers.find((r) => r.id === ep.resolverId);
        return {
          ip,
          kind: "resolverInbound",
          resourceId: ep.resolverId ?? ep.id,
          name: resolver?.name ?? ep.name,
          vnetId: resolver?.vnetId ?? vnetOfSubnet(ep.subnetIds[0]),
        };
      }
      const fw = firewallByIp.get(ip);
      if (fw) return { ip, kind: "firewall", resourceId: fw.id, name: fw.name, vnetId: vnetOfIp(ip) };
      const owner = vnetOfIp(ip);
      return owner
        ? { ip, kind: "vnet", vnetId: owner, name: vnetName.get(owner) }
        : { ip, kind: "external" };
    });
    const resolving =
      custom.length === 0 ? [v.id] : [...new Set(servers.flatMap((s) => (s.vnetId ? [s.vnetId] : [])))];
    return {
      vnetId: v.id,
      vnet: v.name,
      mode: custom.length === 0 ? "azure" : "custom",
      servers,
      resolvingVnetIds: resolving,
      verifiable: servers.every((s) => s.kind !== "external"),
      linkedZones: (zonesLinkedTo.get(v.id) ?? []).sort(),
      rulesets: (rulesetsLinkedTo.get(v.id) ?? []).sort(),
    };
  });
  const dnsOfVnet = new Map(vnets.map((v) => [v.vnetId, v]));

  const external = vnets.filter((v) => !v.verifiable);
  if (external.length > 0) {
    const ips = [
      ...new Set(external.flatMap((v) => v.servers.filter((s) => s.kind === "external").map((s) => s.ip))),
    ];
    findings.push(
      finding(
        "dns",
        "INFO",
        "DNS_EXTERNAL_SERVERS",
        `${external.length} VNet(s) nutzen DNS-Server außerhalb der erfassten VNets`,
        `Server ${ips.join(", ")} (z. B. On-Premises). Ob Private-Link-Namen dort korrekt aufgelöst werden (bedingte Weiterleitung an Azure DNS), ist aus der Azure-Konfiguration nicht prüfbar.`,
        external.map((v) => v.vnetId),
      ),
    );
  }
  const modes = new Set(vnets.map((v) => v.mode));
  if (modes.size > 1) {
    const azure = vnets.filter((v) => v.mode === "azure");
    findings.push(
      finding(
        "dns",
        "INFO",
        "DNS_MIXED_CONFIGURATION",
        `Gemischte DNS-Konfiguration: ${azure.length} VNet(s) mit Azure-DNS, ${vnets.length - azure.length} mit eigenen DNS-Servern`,
        "VNets mit Azure-DNS sehen nur die direkt an sie verlinkten Private-DNS-Zonen, nicht die des zentralen DNS.",
        azure.map((v) => v.vnetId),
      ),
    );
  }

  // --- Zones ------------------------------------------------------------------------------------
  const byName = new Map<string, typeof inv.privateDnsZones>();
  for (const z of inv.privateDnsZones)
    byName.set(z.name.toLowerCase(), [...(byName.get(z.name.toLowerCase()) ?? []), z]);
  const zones: ZoneSummary[] = inv.privateDnsZones.map((z) => ({
    id: z.id,
    name: z.name,
    subscriptionId: z.subscriptionId,
    resourceGroup: z.resourceGroup,
    linkedVnetIds: z.vnetLinks.flatMap((l) => (l.vnetId ? [l.vnetId] : [])),
    registrationVnetIds: z.vnetLinks.flatMap((l) => (l.vnetId && l.registrationEnabled ? [l.vnetId] : [])),
    records: z.records.length,
    aRecords: z.aRecordCount,
    sameNameZones: byName.get(z.name.toLowerCase())?.length ?? 1,
  }));
  for (const z of zones) {
    if (z.linkedVnetIds.length === 0)
      findings.push(
        finding(
          "dns",
          "LOW",
          "DNS_ZONE_NOT_LINKED",
          `Private-DNS-Zone ${z.name} ist mit keinem VNet verlinkt`,
          "Ohne VNet-Link beantwortet Azure DNS keine Anfragen aus diesen Records – die Zone ist wirkungslos.",
          [z.id],
        ),
      );
  }
  for (const [name, list] of byName) {
    if (list.length < 2) continue;
    findings.push(
      finding(
        "dns",
        "MEDIUM",
        "DNS_DUPLICATE_ZONE",
        `Private-DNS-Zone ${name} existiert ${list.length}-mal`,
        `In ${list.map((z) => `${z.resourceGroup ?? "?"}`).join(", ")}. Je nach verlinktem VNet liefern die Zonen unterschiedliche Antworten; Records fehlen leicht in einer Kopie (Split-Brain).`,
        list.map((z) => z.id),
      ),
    );
  }

  // --- Resolvers and rulesets -------------------------------------------------------------------
  const resolverSummaries: ResolverSummary[] = resolvers.map((r) => {
    const ips = inbound.filter((e) => e.resolverId === r.id).flatMap((e) => e.privateIps);
    return {
      id: r.id,
      name: r.name,
      vnetId: r.vnetId,
      inboundIps: ips,
      outboundEndpoints: outbound.filter((e) => e.resolverId === r.id).map((e) => e.name),
      usedByVnetIds: vnets.filter((v) => v.servers.some((s) => ips.includes(s.ip))).map((v) => v.vnetId),
    };
  });
  for (const r of resolverSummaries) {
    if (r.inboundIps.length > 0 && r.usedByVnetIds.length === 0)
      findings.push(
        finding(
          "dns",
          "LOW",
          "DNS_RESOLVER_INBOUND_UNUSED",
          `Inbound Endpoint von ${r.name} wird von keinem VNet als DNS-Server genutzt`,
          `Inbound-IPs ${r.inboundIps.join(", ")}. Entweder nutzen die VNets andere DNS-Server oder der Endpoint dient nur On-Premises-Weiterleitungen.`,
          [r.id],
        ),
      );
  }
  const rulesets: RulesetSummary[] = rulesetEntities.map((r) => ({
    id: r.id,
    name: r.name,
    linkedVnetIds: r.linkedVnetIds,
    outboundEndpoints: r.outboundEndpointIds.map(lastSegment),
    rules: r.forwardingRules.map((f) => ({
      name: f.name,
      domain: f.domainName ?? f.name,
      targets: f.targets,
      enabled: (f.state ?? "Enabled").toLowerCase() !== "disabled",
    })),
  }));
  for (const r of rulesets) {
    if (r.linkedVnetIds.length === 0)
      findings.push(
        finding(
          "dns",
          "LOW",
          "DNS_RULESET_NOT_LINKED",
          `Weiterleitungs-Regelsatz ${r.name} ist mit keinem VNet verlinkt`,
          "Die Regeln werden nie angewendet.",
          [r.id],
        ),
      );
    const customLinked = r.linkedVnetIds.filter((v) => dnsOfVnet.get(v)?.mode === "custom");
    if (customLinked.length > 0)
      findings.push(
        finding(
          "dns",
          "INFO",
          "DNS_RULESET_ON_CUSTOM_DNS_VNET",
          `Regelsatz ${r.name} ist an ${customLinked.length} VNet(s) mit eigenen DNS-Servern verlinkt`,
          "Weiterleitungsregeln greifen nur für Anfragen an Azure DNS. Sie wirken dort nur, wenn die eigenen DNS-Server selbst an Azure DNS weiterleiten.",
          [r.id, ...customLinked],
        ),
      );
    const disabled = r.rules.filter((x) => !x.enabled);
    if (disabled.length > 0)
      findings.push(
        finding(
          "dns",
          "INFO",
          "DNS_FORWARDING_RULE_DISABLED",
          `${disabled.length} deaktivierte Weiterleitungsregel(n) in ${r.name}`,
          disabled.map((x) => x.domain).join(", "),
          [r.id],
        ),
      );
  }

  // --- Private endpoint resolution ----------------------------------------------------------------
  const privateEndpoints = inv.privateEndpoints.flatMap((pe) =>
    checkPrivateEndpoint(pe, inv, dnsOfVnet, rulesets),
  );
  const peName = new Map(inv.privateEndpoints.map((p) => [p.id, p.name]));
  const SEVERITY: Record<PeDnsStatus, Finding["severity"] | undefined> = {
    ok: undefined,
    "missing-zone": "HIGH",
    "missing-record": "HIGH",
    "not-linked": "HIGH",
    "unknown-zone": "LOW",
    unverifiable: undefined,
    inactive: "LOW",
  };
  const TITLE: Record<PeDnsStatus, string> = {
    ok: "",
    "missing-zone": "keine passende Private-DNS-Zone",
    "missing-record": "kein A-Record mit der privaten IP",
    "not-linked": "Zone nicht mit dem auflösenden VNet verlinkt",
    "unknown-zone": "erwartete DNS-Zone unbekannt",
    unverifiable: "",
    inactive: "Verbindung nicht aktiv",
  };
  for (const c of privateEndpoints) {
    const severity = SEVERITY[c.status];
    if (!severity) continue;
    findings.push(
      finding(
        "dns",
        severity,
        `PE_DNS_${c.status.toUpperCase().replace(/-/g, "_")}`,
        `Private Endpoint ${peName.get(c.privateEndpointId) ?? c.privateEndpoint} (${c.target}, ${c.groupId}): ${TITLE[c.status]}`,
        c.detail,
        [c.privateEndpointId, c.targetId, ...c.zoneIds],
      ),
    );
  }
  const unverifiable = privateEndpoints.filter((c) => c.status === "unverifiable");
  if (unverifiable.length > 0)
    findings.push(
      finding(
        "dns",
        "INFO",
        "PE_DNS_UNVERIFIABLE",
        `${unverifiable.length} Private-Endpoint-Auflösung(en) nicht prüfbar`,
        "Die VNets nutzen externe DNS-Server oder leiten die Domain per Regelsatz weiter; die Auflösung hängt von Systemen außerhalb der Azure-Konfiguration ab.",
        [...new Set(unverifiable.map((c) => c.privateEndpointId))],
      ),
    );

  return { vnets, zones, resolvers: resolverSummaries, rulesets, privateEndpoints, findings };
}

function checkPrivateEndpoint(
  pe: PrivateEndpointEntity,
  inv: NormalizedInventory,
  dnsOfVnet: Map<string, VnetDnsSetting>,
  rulesets: RulesetSummary[],
): PeDnsCheck[] {
  const vnetId = vnetOfSubnet(pe.subnetId);
  const dns = vnetId ? dnsOfVnet.get(vnetId) : undefined;
  const ips = pe.addressing.ipv4;
  const fqdns = pe.customDnsConfigs.flatMap((c) => (c.fqdn ? [c.fqdn] : []));
  return pe.targets.flatMap((t) =>
    (t.groupIds.length ? t.groupIds : ["?"]).map((groupId): PeDnsCheck => {
      const expectedZones = expectedZonesFor(groupId, fqdns);
      const zonesFound = inv.privateDnsZones.filter((z) =>
        expectedZones.some((e) => zoneMatches(e.toLowerCase(), z.name.toLowerCase())),
      );
      const recordZones = zonesFound.filter((z) =>
        z.records.some((r) => r.recordType === "A" && r.values.some((v) => ips.includes(v))),
      );
      const resolving = dns?.resolvingVnetIds ?? (vnetId ? [vnetId] : []);
      const linked = recordZones.filter((z) =>
        z.vnetLinks.some((l) => l.vnetId && resolving.includes(l.vnetId)),
      );
      const forwarded = rulesets.find(
        (r) =>
          r.linkedVnetIds.some((v) => resolving.includes(v)) &&
          r.rules.some(
            (rule) =>
              rule.enabled &&
              expectedZones.some((z) => {
                const d = trimDot(rule.domain);
                const plain = z.replace(/^privatelink\./, "");
                return z === d || z.endsWith(`.${d}`) || plain === d || plain.endsWith(`.${d}`);
              }),
          ),
      );
      // A record with the endpoint IP in a zone Azure does not query for this name (e.g. custom names).
      const elsewhere = inv.privateDnsZones.filter(
        (z) =>
          !zonesFound.includes(z) &&
          z.records.some((r) => r.recordType === "A" && r.values.some((v) => ips.includes(v))),
      );
      const elsewhereNote = () =>
        elsewhere.length
          ? ` Ein A-Record mit dieser IP steht in ${elsewhere.map((z) => z.name).join(", ")} – diese Zone wird für den Private-Link-Namen nicht abgefragt.`
          : "";
      const base = {
        privateEndpointId: pe.id,
        privateEndpoint: pe.name,
        vnetId,
        targetId: t.resourceId,
        target: lastSegment(t.resourceId),
        groupId,
        ips,
        expectedZones,
        zoneIds: zonesFound.map((z) => z.id),
        recordZoneIds: recordZones.map((z) => z.id),
        linkedZoneIds: linked.map((z) => z.id),
        resolvingVnetIds: resolving,
      };
      const resolverNames = resolving.map((v) => dnsOfVnet.get(v)?.vnet ?? lastSegment(v)).join(", ");
      const zoneList = (list: typeof zonesFound) =>
        list.map((z) => `${z.name} (${z.resourceGroup ?? "?"})`).join(", ");
      if ((t.status ?? "Approved").toLowerCase() !== "approved")
        return {
          ...base,
          status: "inactive",
          detail: `Verbindungsstatus „${t.status}“ – der Endpoint leitet keinen Verkehr weiter. Aufräumen oder Verbindung neu genehmigen.`,
        };
      if (expectedZones.length === 0)
        return {
          ...base,
          status: "unknown-zone",
          detail: `Für die Gruppe „${groupId}" ist keine Zone bekannt und die Endpoint-Konfiguration enthält keinen FQDN.`,
        };
      if (linked.length > 0)
        return {
          ...base,
          status: "ok",
          detail: `A-Record mit ${ips.join(", ")} in ${linked.map((z) => z.name).join(", ")}, verlinkt mit ${resolverNames}.`,
        };
      if (forwarded)
        return {
          ...base,
          status: "unverifiable",
          detail: `Die Domain wird über Regelsatz ${forwarded.name} weitergeleitet; die Antwort kommt von einem anderen DNS-Server.`,
        };
      if (dns && !dns.verifiable && (zonesFound.length === 0 || recordZones.length > 0))
        return {
          ...base,
          status: "unverifiable",
          detail: `Das VNet nutzt DNS-Server außerhalb Azure (${dns.servers
            .filter((s) => s.kind === "external")
            .map((s) => s.ip)
            .join(", ")}); ob dort ${expectedZones[0]} korrekt auflöst, ist nicht prüfbar.`,
        };
      if (zonesFound.length === 0)
        return {
          ...base,
          status: "missing-zone",
          detail: `Erwartet: ${expectedZones.join(" oder ")}. Ohne Zone löst der Name auf die öffentliche IP auf – ist der öffentliche Zugriff gesperrt, schlägt die Verbindung fehl.${elsewhereNote()}`,
        };
      if (recordZones.length === 0)
        return {
          ...base,
          status: "missing-record",
          detail: `${zoneList(zonesFound)} vorhanden, aber ohne A-Record auf ${ips.join(", ") || "die private IP"} (DNS-Zonengruppe am Endpoint fehlt?).${elsewhereNote()}`,
        };
      return {
        ...base,
        status: "not-linked",
        detail: `Record in ${zoneList(recordZones)}, aber die Zone ist nicht mit dem auflösenden VNet (${resolverNames}) verlinkt.`,
      };
    }),
  );
}
