#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Command, InvalidArgumentError, Option } from "commander";
import { createNodeCredential, CREDENTIAL_KINDS, isCredentialKind } from "../auth/node/credential.js";
import { createLogger, jsonLinesSink, type LogLevel } from "../logging/logger.js";
import { runDiscovery } from "../discovery/runDiscovery.js";
import { assessmentFileName, buildAssessmentExport } from "../export/assessmentJson.js";
import { analyzeInventory } from "../pipeline/analyze.js";
import { FileCache } from "./fileCache.js";

const collect = (value: string, previous: string[] = []): string[] => [...previous, value];

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const guid = (value: string, previous: string[] = []): string[] => {
  if (!GUID.test(value)) throw new InvalidArgumentError(`not a GUID: ${value}`);
  return collect(value, previous);
};

const program = new Command()
  .name("azure-network-audit")
  .description("Read-only Azure network discovery and assessment");

program
  .command("discover")
  .description("Discover tenants, subscriptions and network resources via Azure Resource Graph (read-only)")
  .addOption(
    new Option("--credential <kind>", "credential source").choices([...CREDENTIAL_KINDS]).default("default"),
  )
  .option("--tenant <id>", "limit to tenant (repeatable)", guid)
  .option("--subscription <id>", "limit to subscription (repeatable)", guid)
  .option("--out <dir>", "output directory", "output")
  .option("--no-cache", "bypass the discovery cache")
  .option("--no-management-groups", "skip management group discovery")
  .option("--no-enrichment", "skip ARM enrichment (Virtual WAN details, service tag prefixes)")
  .addOption(
    new Option("--log-level <level>", "log level")
      .choices(["debug", "info", "warn", "error"])
      .default("info"),
  )
  .action(
    async (opts: {
      credential: string;
      tenant?: string[];
      subscription?: string[];
      out: string;
      cache: boolean;
      managementGroups: boolean;
      enrichment: boolean;
      logLevel: LogLevel;
    }) => {
      if (!isCredentialKind(opts.credential)) throw new InvalidArgumentError(opts.credential);
      // Logs go to stderr as JSON lines so stdout stays clean for piping.
      const logger = createLogger({
        sink: jsonLinesSink((line) => process.stderr.write(`${line}\n`)),
        level: opts.logLevel,
      });
      const outDir = resolve(opts.out);
      const inventory = await runDiscovery({
        credential: createNodeCredential(opts.credential),
        logger,
        cache: opts.cache ? new FileCache(resolve(".cache", "discovery")) : undefined,
        includeManagementGroups: opts.managementGroups,
        enrich: opts.enrichment,
        ...(opts.tenant ? { tenantIds: opts.tenant } : {}),
        ...(opts.subscription ? { subscriptionIds: opts.subscription } : {}),
      });
      await mkdir(outDir, { recursive: true });
      const file = join(outDir, "raw-inventory.json");
      await writeFile(file, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");
      const now = new Date();
      const model = analyzeInventory(inventory);
      const exportDocument = `${JSON.stringify(buildAssessmentExport(model, { now }), null, 2)}\n`;
      const exportFile = join(outDir, assessmentFileName(now));
      await writeFile(exportFile, exportDocument, "utf8");
      await writeFile(join(outDir, "network-assessment.json"), exportDocument, "utf8");

      const q = inventory.quality;
      process.stdout.write(
        [
          `Raw inventory:     ${file}`,
          `Network model:     ${exportFile}`,
          `Graph:             ${model.graph.nodes.length} nodes, ${model.graph.edges.length} relationships`,
          `Hubs / spokes:     ${model.inventory.vnets.filter((v) => v.topology?.classification === "hub").length} / ${model.inventory.vnets.filter((v) => v.topology?.classification === "spoke").length}`,
          `Tenants:           ${q.tenants.readable}/${q.tenants.total} readable`,
          `Subscriptions:     ${q.subscriptions.readable}/${q.subscriptions.total} readable`,
          `Network resources: ${q.networkResources}`,
          `ARG queries:       ${q.argQueries.executed} (${q.argQueries.pages} pages, ${q.argQueries.failed} failed, ${q.argQueries.truncated} truncated)`,
          `ARM enrichment:    ${q.armEnrichment.successful}/${q.armEnrichment.attempted} calls ok, service tags: ${inventory.enrichment?.serviceTags?.tags.length ?? 0}`,
          `Warnings:          ${inventory.warnings.length}`,
          `Confidence:        ${q.overallConfidence}`,
          "",
        ].join("\n"),
      );
      // Exit code 2 = discovery completed but incomplete (see ARCHITECTURE.md § 19).
      if (inventory.warnings.some((w) => !w.optional) || q.overallConfidence !== "HIGH") process.exitCode = 2;
    },
  );

program.parseAsync().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`);
  process.exitCode = 1;
});
