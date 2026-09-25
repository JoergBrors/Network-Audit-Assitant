import type { AccessToken, GetTokenOptions, TokenCredential } from "@azure/core-auth";

export const ARM_SCOPE = "https://management.azure.com/.default";
export const ARM_USER_IMPERSONATION_SCOPE = "https://management.azure.com/user_impersonation";

/**
 * Binds a credential to one tenant. Azure SDK clients only pass `tenantId` on claims challenges,
 * so multi-tenant discovery needs this wrapper to obtain a token issued by the right tenant.
 */
export function tenantBoundCredential(base: TokenCredential, tenantId: string): TokenCredential {
  return {
    getToken(scopes: string | string[], options?: GetTokenOptions): Promise<AccessToken | null> {
      return base.getToken(scopes, { ...options, tenantId: options?.tenantId ?? tenantId });
    },
  };
}
