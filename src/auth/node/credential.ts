import type { TokenCredential } from "@azure/core-auth";
import {
  AzureCliCredential,
  DefaultAzureCredential,
  ManagedIdentityCredential,
  VisualStudioCodeCredential,
  WorkloadIdentityCredential,
} from "@azure/identity";

export const CREDENTIAL_KINDS = ["default", "cli", "vscode", "mi", "workload"] as const;
export type CredentialKind = (typeof CREDENTIAL_KINDS)[number];

export function isCredentialKind(value: string): value is CredentialKind {
  return (CREDENTIAL_KINDS as readonly string[]).includes(value);
}

/**
 * CLI credential. No secrets are read from source; only the standard Azure identity sources
 * (environment, workload identity, managed identity, VS Code, Azure CLI) are used.
 * `additionallyAllowedTenants: ["*"]` enables tenant-bound tokens for multi-tenant discovery.
 */
export function createNodeCredential(kind: CredentialKind = "default"): TokenCredential {
  const allTenants = { additionallyAllowedTenants: ["*"] };
  switch (kind) {
    case "cli":
      return new AzureCliCredential(allTenants);
    case "vscode":
      return new VisualStudioCodeCredential(allTenants);
    case "mi":
      return new ManagedIdentityCredential();
    case "workload":
      return new WorkloadIdentityCredential(allTenants);
    case "default":
      return new DefaultAzureCredential(allTenants);
  }
}
