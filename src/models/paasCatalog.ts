/**
 * PaaS services with network endpoints (public endpoint, firewall, Private Link, VNet integration)
 * that the discovery reads (RESOURCE-GRAPH-QUERIES.md § 8a). Types are lowercase ARM types.
 */
export type PaasCategory =
  "storage" | "database" | "web" | "security" | "integration" | "ai" | "containers" | "analytics" | "other";

export interface PaasServiceType {
  type: string;
  label: string;
  category: PaasCategory;
  /** Data services where an open public endpoint weighs heavier in the assessment. */
  sensitive?: boolean;
}

export const PAAS_SERVICE_TYPES: readonly PaasServiceType[] = [
  {
    type: "microsoft.storage/storageaccounts",
    label: "Storage Account",
    category: "storage",
    sensitive: true,
  },
  { type: "microsoft.sql/servers", label: "Azure SQL Server", category: "database", sensitive: true },
  {
    type: "microsoft.sql/managedinstances",
    label: "SQL Managed Instance",
    category: "database",
    sensitive: true,
  },
  {
    type: "microsoft.dbforpostgresql/flexibleservers",
    label: "PostgreSQL Flexible Server",
    category: "database",
    sensitive: true,
  },
  {
    type: "microsoft.dbformysql/flexibleservers",
    label: "MySQL Flexible Server",
    category: "database",
    sensitive: true,
  },
  {
    type: "microsoft.documentdb/databaseaccounts",
    label: "Cosmos DB",
    category: "database",
    sensitive: true,
  },
  { type: "microsoft.cache/redis", label: "Azure Cache for Redis", category: "database", sensitive: true },
  { type: "microsoft.keyvault/vaults", label: "Key Vault", category: "security", sensitive: true },
  { type: "microsoft.web/sites", label: "App Service / Function App", category: "web" },
  { type: "microsoft.web/staticsites", label: "Static Web App", category: "web" },
  { type: "microsoft.apimanagement/service", label: "API Management", category: "integration" },
  { type: "microsoft.servicebus/namespaces", label: "Service Bus", category: "integration" },
  { type: "microsoft.eventhub/namespaces", label: "Event Hubs", category: "integration" },
  { type: "microsoft.eventgrid/topics", label: "Event Grid Topic", category: "integration" },
  { type: "microsoft.eventgrid/domains", label: "Event Grid Domain", category: "integration" },
  { type: "microsoft.signalrservice/signalr", label: "SignalR", category: "integration" },
  {
    type: "microsoft.appconfiguration/configurationstores",
    label: "App Configuration",
    category: "integration",
  },
  { type: "microsoft.automation/automationaccounts", label: "Automation Account", category: "integration" },
  { type: "microsoft.cognitiveservices/accounts", label: "Azure AI Services / OpenAI", category: "ai" },
  { type: "microsoft.search/searchservices", label: "Azure AI Search", category: "ai" },
  {
    type: "microsoft.machinelearningservices/workspaces",
    label: "Azure Machine Learning",
    category: "ai",
  },
  { type: "microsoft.containerregistry/registries", label: "Container Registry", category: "containers" },
  { type: "microsoft.containerservice/managedclusters", label: "AKS", category: "containers" },
  { type: "microsoft.app/managedenvironments", label: "Container Apps Environment", category: "containers" },
  { type: "microsoft.app/containerapps", label: "Container App", category: "containers" },
  { type: "microsoft.datafactory/factories", label: "Data Factory", category: "analytics" },
  { type: "microsoft.synapse/workspaces", label: "Synapse Workspace", category: "analytics" },
  { type: "microsoft.databricks/workspaces", label: "Databricks", category: "analytics" },
  { type: "microsoft.purview/accounts", label: "Purview", category: "analytics" },
  { type: "microsoft.insights/components", label: "Application Insights", category: "other" },
  { type: "microsoft.operationalinsights/workspaces", label: "Log Analytics Workspace", category: "other" },
];

export const PAAS_TYPE_INFO = new Map(PAAS_SERVICE_TYPES.map((t) => [t.type, t]));

/**
 * Private DNS zone per Private Link group ID (Microsoft Learn: private-endpoint-dns). Used when the
 * private endpoint has no FQDN in customDnsConfigs to derive the zone from. `{region}` is replaced.
 */
export const PRIVATE_LINK_ZONES: Record<string, string[]> = {
  blob: ["privatelink.blob.core.windows.net"],
  blob_secondary: ["privatelink.blob.core.windows.net"],
  table: ["privatelink.table.core.windows.net"],
  table_secondary: ["privatelink.table.core.windows.net"],
  queue: ["privatelink.queue.core.windows.net"],
  queue_secondary: ["privatelink.queue.core.windows.net"],
  file: ["privatelink.file.core.windows.net"],
  web: ["privatelink.web.core.windows.net"],
  web_secondary: ["privatelink.web.core.windows.net"],
  dfs: ["privatelink.dfs.core.windows.net"],
  dfs_secondary: ["privatelink.dfs.core.windows.net"],
  sqlserver: ["privatelink.database.windows.net"],
  managedinstance: ["privatelink.{region}.database.windows.net"],
  postgresqlserver: ["privatelink.postgres.database.azure.com"],
  mysqlserver: ["privatelink.mysql.database.azure.com"],
  sql: ["privatelink.documents.azure.com"],
  mongodb: ["privatelink.mongo.cosmos.azure.com"],
  cassandra: ["privatelink.cassandra.cosmos.azure.com"],
  gremlin: ["privatelink.gremlin.cosmos.azure.com"],
  rediscache: ["privatelink.redis.cache.windows.net"],
  vault: ["privatelink.vaultcore.azure.net"],
  sites: ["privatelink.azurewebsites.net"],
  staticsites: ["privatelink.azurestaticapps.net"],
  gateway: ["privatelink.azure-api.net"],
  namespace: ["privatelink.servicebus.windows.net"],
  topic: ["privatelink.eventgrid.azure.net"],
  domain: ["privatelink.eventgrid.azure.net"],
  signalr: ["privatelink.service.signalr.net"],
  configurationstores: ["privatelink.azconfig.io"],
  webhook: ["privatelink.azure-automation.net"],
  dscandhybridworker: ["privatelink.azure-automation.net"],
  account: ["privatelink.cognitiveservices.azure.com", "privatelink.openai.azure.com"],
  searchservice: ["privatelink.search.windows.net"],
  amlworkspace: ["privatelink.api.azureml.ms", "privatelink.notebooks.azure.net"],
  registry: ["privatelink.azurecr.io"],
  management: ["privatelink.{region}.azmk8s.io"],
  managedenvironments: ["privatelink.{region}.azurecontainerapps.io"],
  datafactory: ["privatelink.datafactory.azure.net"],
  portal: ["privatelink.adf.azure.com"],
  dev: ["privatelink.dev.azuresynapse.net"],
  sqlondemand: ["privatelink.sql.azuresynapse.net"],
  databricks_ui_api: ["privatelink.azuredatabricks.net"],
  azuremonitor: ["privatelink.monitor.azure.com"],
};
