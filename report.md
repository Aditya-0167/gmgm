# gemini-cli MCP OAuth token disclosure via name-only credential lookup (no server-identity binding)

**Program:** Cloud VRP (confirmed `TIER_OT1`/`SCOPE_CLOUD_VRP` for this repo, per `google/bughunters`)
**Repository:** https://github.com/google-gemini/gemini-cli
**Files:**
- `packages/core/src/mcp/oauth-token-storage.ts` (`MCPOAuthTokenStorage.getCredentials`, `.saveToken`)
- `packages/core/src/mcp/oauth-provider.ts` (`MCPOAuthProvider.getValidToken`)
**Vulnerability class:** CWE-346 (Origin Validation Error) / Improper Verification of Credential Binding

## The problem

`OAuthCredentials` (`packages/core/src/mcp/token-storage/types.ts`) records the actual server URL a token was issued for:
```ts
export interface OAuthCredentials {
  serverName: string;
  token: OAuthToken;
  clientId?: string;
  tokenUrl?: string;
  mcpServerUrl?: string;   // <-- captured at save time
  updatedAt: number;
}
```
`saveToken()` populates it correctly. But every retrieval path keys **purely by `serverName`**:
```ts
// oauth-token-storage.ts
async getCredentials(serverName: string): Promise<OAuthCredentials | null> {
  const tokens = await this.getAllCredentials();
  return tokens.get(serverName) || null;
}
```
And `getValidToken()` (`oauth-provider.ts`), which is what actually hands back the string that gets placed in the connection's Authorization header, never reads `credentials.mcpServerUrl` at all:
```ts
async getValidToken(serverName: string, config: MCPOAuthConfig): Promise<string | null> {
  const credentials = await this.tokenStorage.getCredentials(serverName);
  if (!credentials) return null;
  const { token } = credentials;
  if (!this.tokenStorage.isTokenExpired(token)) {
    return token.accessToken;   // <-- returned with zero check against the URL being connected to now
  }
  ...
}
```
Confirmed via `packages/core/src/tools/mcp-client.ts`: this return value flows directly into the SSE/HTTP transport's Authorization header for whatever URL the *current* server config under that name specifies — not necessarily the URL the token was originally issued for.

**Net effect: an OAuth token is bound to a human-chosen label string, not to the server identity it was actually issued for.**

## Reachability — two independent paths, no chained exploit required for either

1. **Malicious repo, already-established attack chain:** once a repository's `mcpServers` config is honored (per the already-reported `isTrusted` bypass, issue 560548851), a malicious entry naming itself after a service the user has already authenticated (`"notion"`, `"github"`, `"slack"`, `"google-drive"`, etc.) but pointing its own `url`/`httpUrl` at an attacker-controlled endpoint receives that service's real token on connect.
2. **Fully legitimate scenario, no bypass needed:** two different workspaces the user has each individually, properly consented to trust (ordinary `trustedFolders` consent, no bug involved) happen to declare an MCP server under the same name for two genuinely different actual endpoints. The token saved for the first is sent to the second the next time that name is used. This path requires no exploit of any other vulnerability — it's a direct consequence of name-only binding.

## Proof of Concept

`poc_oauth_name_collision.ts` (attached) extracts `getCredentials`, `setCredentials`, `saveToken`, `isTokenExpired`, and `getValidToken` byte-for-byte from the two files above (only unrelated names — `debugLogger`, `coreEvents`, the unreached token-refresh branch — are stubbed). Run:

```
Saved: server name "notion" -> token issued for https://real-notion-mcp.example.com/sse
Attacker's config for name "notion" points at https://attacker.evil.example/sse
getValidToken("notion", ...) returned: SECRET_REAL_NOTION_TOKEN_abc123
LEAK CONFIRMED
```

GitHub Actions workflow included (`.github/workflows/poc.yml`): runs the PoC, then independently clones `gemini-cli` fresh and greps for the two vulnerable lines to confirm they're unpatched on current `main`.

## Impact analysis

Any MCP server the user has OAuth-authenticated through gemini-cli — a real, standing credential for a genuine third-party service (Notion, GitHub, Slack, Google Drive, or any other OAuth-backed MCP integration) — can be handed to a different endpoint simply by that endpoint's config reusing the same server name. Unlike the a2a-server bug's impact (command execution confined to the a2a-server host), this discloses a **real credential usable directly against a real third-party API**, independent of gemini-cli entirely, and independent of session lifetime — the attacker can use the stolen token for as long as it remains valid, from anywhere.

## Suggested fix

Bind the credential lookup to server identity, not just the human-chosen name — e.g., store and require a match on `mcpServerUrl` (or a canonicalized form of it) at `getCredentials`/`getValidToken` time, and refuse to return a token when the current config's URL doesn't match what was recorded at save time.
