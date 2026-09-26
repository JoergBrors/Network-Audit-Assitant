import type { NormalizedInventory } from "../models/network.js";
import { assessDns, type DnsAssessment } from "./dns.js";
import { assessPaas, type PaasSummary } from "./paas.js";
import { sortFindings, type Finding } from "./types.js";

export interface ServiceAssessment {
  dns: DnsAssessment;
  paas: PaasSummary;
  /** PaaS and DNS findings, most severe first. */
  findings: Finding[];
}

const cache = new WeakMap<NormalizedInventory, ServiceAssessment>();

/**
 * Rule-based assessment of PaaS endpoints and DNS (deterministic, no network calls). Cached per
 * inventory object, so UI components can call it freely.
 */
export function assessServices(inv: NormalizedInventory): ServiceAssessment {
  const cached = cache.get(inv);
  if (cached) return cached;
  const dns = assessDns(inv);
  const paas = assessPaas(inv, dns.privateEndpoints);
  const result = { dns, paas: paas.summary, findings: sortFindings([...paas.findings, ...dns.findings]) };
  cache.set(inv, result);
  return result;
}

export type { Finding, Severity } from "./types.js";
export type { DnsAssessment, PeDnsCheck, VnetDnsSetting } from "./dns.js";
