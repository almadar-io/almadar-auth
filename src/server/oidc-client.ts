import * as oidc from 'openid-client';
import { PENDING_GRANT_TTL_MS, pendingGrantStore, type PendingAuthorization } from './pending-grants.js';

export type OidcServerMetadata = oidc.ServerMetadata;

/**
 * Where a client finds its authorization server: an OIDC issuer (discovered), or static metadata
 * for a plain OAuth 2 provider without a discovery document (secret sent in the token body).
 */
export type OidcServer = { issuer: string } | { metadata: OidcServerMetadata };

export interface OidcClientConfig {
  /** Tag stored on each pending grant, naming this client. */
  provider: string;
  clientId: string;
  clientSecret: string;
  server: OidcServer;
}

export interface OidcAuthorizeInput {
  redirectUri: string;
  scopes: readonly string[];
  subject?: string;
  /** Provider-specific authorization parameters (e.g. Google's offline consent). */
  params?: Readonly<Record<string, string>>;
}

export interface OidcTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  scope: string[];
  /** The ID token's `sub`, when the provider returned one. */
  idTokenSubject?: string;
}

export interface OidcUserInfo {
  sub: string;
  email?: string;
  name?: string;
  picture?: string;
}

/** Scopes a token response granted: providers separate them with spaces (RFC 6749) or commas (GitHub). */
function grantedScopes(scope: string | undefined): string[] {
  return (scope ?? '').split(/[\s,]+/).filter((s) => s.length > 0);
}

function tokensOf(response: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers): OidcTokens {
  const sub = response.claims()?.sub;
  return {
    accessToken: response.access_token,
    ...(response.refresh_token !== undefined ? { refreshToken: response.refresh_token } : {}),
    ...(response.expires_in !== undefined ? { expiresIn: response.expires_in } : {}),
    scope: grantedScopes(response.scope),
    ...(sub !== undefined ? { idTokenSubject: sub } : {}),
  };
}

/** The one authorization-code + PKCE client: app sign-in (generic OIDC) and "connect your account" both use it. */
export class OidcClient {
  private configuration: Promise<oidc.Configuration> | null = null;

  constructor(private readonly config: OidcClientConfig) {}

  get provider(): string {
    return this.config.provider;
  }

  private resolve(): Promise<oidc.Configuration> {
    const { server, clientId, clientSecret } = this.config;
    this.configuration ??= ('issuer' in server
      ? oidc.discovery(new URL(server.issuer), clientId, clientSecret)
      : Promise.resolve(new oidc.Configuration(server.metadata, clientId, clientSecret, oidc.ClientSecretPost(clientSecret)))
    ).catch((error: Error) => {
      this.configuration = null;
      throw error;
    });
    return this.configuration;
  }

  /** Build the authorization URL and hold the pending grant (PKCE verifier, subject) under a fresh `state`. */
  async authorize(input: OidcAuthorizeInput): Promise<{ authUrl: string; state: string }> {
    const configuration = await this.resolve();
    const state = oidc.randomState();
    const pkceVerifier = oidc.randomPKCECodeVerifier();
    const authUrl = oidc.buildAuthorizationUrl(configuration, {
      ...input.params,
      redirect_uri: input.redirectUri,
      scope: input.scopes.join(' '),
      state,
      code_challenge: await oidc.calculatePKCECodeChallenge(pkceVerifier),
      code_challenge_method: 'S256',
    });
    const grant: PendingAuthorization = {
      provider: this.config.provider,
      redirectUri: input.redirectUri,
      pkceVerifier,
      ...(input.subject !== undefined ? { subject: input.subject } : {}),
    };
    await pendingGrantStore().put(state, grant, PENDING_GRANT_TTL_MS);
    void pendingGrantStore().sweep();
    return { authUrl: authUrl.toString(), state };
  }

  /** Exchange the code of a grant taken with `takePendingGrant`. */
  async exchange(grant: PendingAuthorization, code: string, state: string): Promise<OidcTokens> {
    if (grant.provider !== this.config.provider) {
      throw new Error(`grant was issued by ${grant.provider}, not ${this.config.provider}`);
    }
    const callbackUrl = new URL(grant.redirectUri);
    callbackUrl.searchParams.set('code', code);
    callbackUrl.searchParams.set('state', state);
    return tokensOf(await oidc.authorizationCodeGrant(await this.resolve(), callbackUrl, {
      expectedState: state,
      pkceCodeVerifier: grant.pkceVerifier,
    }));
  }

  async refresh(refreshToken: string): Promise<OidcTokens> {
    return tokensOf(await oidc.refreshTokenGrant(await this.resolve(), refreshToken));
  }

  async revoke(token: string): Promise<void> {
    await oidc.tokenRevocation(await this.resolve(), token);
  }

  /** `expectedSubject` is the ID token's `sub` when known; the userinfo response must match it. */
  async userinfo(accessToken: string, expectedSubject: string | undefined): Promise<OidcUserInfo> {
    const info = await oidc.fetchUserInfo(await this.resolve(), accessToken, expectedSubject ?? oidc.skipSubjectCheck);
    return {
      sub: info.sub,
      ...(typeof info.email === 'string' ? { email: info.email } : {}),
      ...(typeof info.name === 'string' ? { name: info.name } : {}),
      ...(typeof info.picture === 'string' ? { picture: info.picture } : {}),
    };
  }
}
