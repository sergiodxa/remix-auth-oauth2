import {
  AppLoadContext,
  redirect,
  SessionStorage,
} from "@remix-run/server-runtime";
import createDebug from "debug";
import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";
import { v4 as uuid } from "uuid";

let debug = createDebug("OAuth2Strategy");

export interface OAuth2Profile {
  provider: string;
  id?: string;
  displayName?: string;
  name?: {
    familyName?: string;
    givenName?: string;
    middleName?: string;
  };
  emails?: Array<{
    value: string;
    type?: string;
  }>;
  photos?: Array<{ value: string }>;
}

type ResponseType =
  | "id_token"
  | "token"
  | "id_token token"
  | "code"
  | "code id_token"
  | "code id_token token";

export interface OAuth2StrategyOptions {
  authorizationURL: string;
  tokenURL: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string;
  responseType?: ResponseType;
  useBasicAuthenticationHeader?: boolean;
}

export interface OAuth2StrategyVerifyParams<
  Profile extends OAuth2Profile,
  ExtraParams extends Record<string, unknown> = Record<string, never>,
> {
  accessToken: string;
  refreshToken?: string;
  extraParams: ExtraParams;
  profile: Profile;
  context?: AppLoadContext;
  request: Request;
}

/**
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * returning the resulting user object.
 *
 * An AuthorizationError should be raised to indicate an authentication failure.
 *
 * Options:
 * - `authorizationURL`  URL used to obtain an authorization grant
 * - `tokenURL`          URL used to obtain an access token
 * - `clientID`          identifies client to service provider
 * - `clientSecret`      secret used to establish ownership of the client identifier
 * - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *
 * @example
 * authenticator.use(new OAuth2Strategy(
 *   {
 *     authorizationURL: 'https://www.example.com/oauth2/authorize',
 *     tokenURL: 'https://www.example.com/oauth2/token',
 *     clientID: '123-456-789',
 *     clientSecret: 'shhh-its-a-secret'
 *     callbackURL: 'https://www.example.net/auth/example/callback'
 *   },
 *   async ({ accessToken, refreshToken, profile }) => {
 *     return await User.findOrCreate(...);
 *   }
 * ));
 */
export class OAuth2Strategy<
  User,
  Profile extends OAuth2Profile,
  ExtraParams extends Record<string, unknown> = Record<string, never>,
> extends Strategy<User, OAuth2StrategyVerifyParams<Profile, ExtraParams>> {
  name = "oauth2";

  protected authorizationURL: string;
  protected tokenURL: string;
  protected clientID: string;
  protected clientSecret: string;
  protected callbackURL: string;
  protected responseType: ResponseType;
  protected useBasicAuthenticationHeader: boolean;
  protected scope?: string;

  private sessionStateKey = "oauth2:state";

  constructor(
    options: OAuth2StrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<Profile, ExtraParams>
    >,
  ) {
    super(verify);
    this.authorizationURL = options.authorizationURL;
    this.tokenURL = options.tokenURL;
    this.clientID = options.clientID;
    this.clientSecret = options.clientSecret;
    this.callbackURL = options.callbackURL;
    this.scope = options.scope;
    this.responseType = options.responseType ?? "code";
    this.useBasicAuthenticationHeader =
      options.useBasicAuthenticationHeader ?? false;
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
  ): Promise<User> {
    debug("Request URL", request.url);
    let url = new URL(request.url);
    let session = await sessionStorage.getSession(
      request.headers.get("Cookie"),
    );

    let user: User | null = session.get(options.sessionKey) ?? null;

    // User is already authenticated
    if (user) {
      debug("User is authenticated");
      return this.success(user, request, sessionStorage, options);
    }

    let callbackURL = this.getCallbackURL(request);

    debug("Callback URL", callbackURL);

    // Redirect the user to the callback URL
    if (url.pathname !== callbackURL.pathname) {
      debug("Redirecting to callback URL");
      let state = this.generateState();
      debug("State", state);
      session.set(this.sessionStateKey, state);
      throw redirect(this.getAuthorizationURL(request, state).toString(), {
        headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
      });
    }

    // Validations of the callback URL params

    let stateUrl = url.searchParams.get("state");
    debug("State from URL", stateUrl);
    if (!stateUrl) {
      return await this.failure(
        "Missing state on URL.",
        request,
        sessionStorage,
        options,
        new Error("Missing state on URL."),
      );
    }

    let stateSession = session.get(this.sessionStateKey);
    debug("State from session", stateSession);
    if (!stateSession) {
      return await this.failure(
        "Missing state on session.",
        request,
        sessionStorage,
        options,
        new Error("Missing state on session."),
      );
    }

    if (stateSession === stateUrl) {
      debug("State is valid");
      session.unset(this.sessionStateKey);
    } else {
      return await this.failure(
        "State doesn't match.",
        request,
        sessionStorage,
        options,
        new Error("State doesn't match."),
      );
    }

    let code = url.searchParams.get("code");
    if (!code) {
      return await this.failure(
        "Missing code.",
        request,
        sessionStorage,
        options,
        new Error("Missing code."),
      );
    }

    try {
      // Get the access token

      let params = new URLSearchParams(this.tokenParams());
      params.set("grant_type", "authorization_code");
      params.set("redirect_uri", callbackURL.toString());

      let { accessToken, refreshToken, extraParams } =
        await this.fetchAccessToken(code, params);

      // Get the profile

      let profile = await this.userProfile(accessToken, extraParams);

      // Verify the user and return it, or redirect

      user = await this.verify({
        accessToken,
        refreshToken,
        extraParams,
        profile,
        context: options.context,
        request,
      });
    } catch (error) {
      debug("Failed to verify user", error);
      // Allow responses to pass-through
      if (error instanceof Response) throw error;
      if (error instanceof Error) {
        return await this.failure(
          error.message,
          request,
          sessionStorage,
          options,
          error,
        );
      }
      if (typeof error === "string") {
        return await this.failure(
          error,
          request,
          sessionStorage,
          options,
          new Error(error),
        );
      }
      return await this.failure(
        "Unknown error",
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2)),
      );
    }

    debug("User authenticated");
    return await this.success(user, request, sessionStorage, options);
  }

  /**
   * Retrieve user profile from service provider.
   *
   * OAuth 2.0-based authentication strategies can override this function in
   * order to load the user's profile from the service provider.  This assists
   * applications (and users of those applications) in the initial registration
   * process by automatically submitting required information.
   */
  protected async userProfile(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    accessToken: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    params: ExtraParams,
  ): Promise<Profile> {
    return { provider: "oauth2" } as Profile;
  }

  /**
   * Return extra parameters to be included in the authorization request.
   *
   * Some OAuth 2.0 providers allow additional, non-standard parameters to be
   * included when requesting authorization.  Since these parameters are not
   * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
   * strategies can override this function in order to populate these
   * parameters as required by the provider.
   */
  protected authorizationParams(params: URLSearchParams): URLSearchParams {
    return new URLSearchParams(params);
  }

  /**
   * Return extra parameters to be included in the token request.
   *
   * Some OAuth 2.0 providers allow additional, non-standard parameters to be
   * included when requesting an access token.  Since these parameters are not
   * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
   * strategies can override this function in order to populate these
   * parameters as required by the provider.
   */
  protected tokenParams(): URLSearchParams {
    return new URLSearchParams();
  }

  protected async getAccessToken(response: Response): Promise<{
    accessToken: string;
    refreshToken?: string;
    extraParams: ExtraParams;
  }> {
    let { access_token, refresh_token, ...extraParams } = await response.json();
    return {
      accessToken: access_token as string,
      refreshToken: refresh_token as string | undefined,
      extraParams,
    } as const;
  }

  private getCallbackURL(request: Request) {
    if (
      this.callbackURL.startsWith("http:") ||
      this.callbackURL.startsWith("https:")
    ) {
      return new URL(this.callbackURL);
    }
    let host =
      request.headers.get("X-Forwarded-Host") ??
      request.headers.get("host") ??
      new URL(request.url).host;
    let protocol = host.includes("localhost") ? "http" : "https";
    if (this.callbackURL.startsWith("/")) {
      return new URL(this.callbackURL, `${protocol}://${host}`);
    }
    return new URL(`${protocol}//${this.callbackURL}`);
  }

  private getAuthorizationURL(request: Request, state: string) {
    let params = new URLSearchParams(
      this.authorizationParams(new URL(request.url).searchParams),
    );
    params.set("response_type", this.responseType);
    params.set("client_id", this.clientID);
    params.set("redirect_uri", this.getCallbackURL(request).toString());
    params.set("state", state);
    // We need to check if `authorizationParams` has not set scopes to avoid regressions on dependent libraries
    if (!params.has("scope") && this.scope) {
      params.set("scope", this.scope);
    }

    let url = new URL(this.authorizationURL);
    url.search = params.toString();

    return url;
  }

  private generateState() {
    return uuid();
  }

  /**
   * Format the data to be sent in the request body to the token endpoint.
   */
  protected async fetchAccessToken(
    code: string,
    params: URLSearchParams,
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    extraParams: ExtraParams;
  }> {
    let headers: HeadersInit = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (this.useBasicAuthenticationHeader) {
      const b64EncodedCredentials = Buffer.from(
        `${this.clientID}:${this.clientSecret}`,
      ).toString("base64");

      headers = {
        ...headers,
        Authorization: `Basic ${b64EncodedCredentials}`,
      };
    } else {
      params.set("client_id", this.clientID);
      params.set("client_secret", this.clientSecret);
    }

    if (params.get("grant_type") === "refresh_token") {
      params.set("refresh_token", code);
    } else {
      params.set("code", code);
    }

    let response = await fetch(this.tokenURL, {
      method: "POST",
      headers,
      body: params,
    });

    if (!response.ok) {
      let body = await response.text();
      throw body;
    }

    return await this.getAccessToken(response.clone() as unknown as Response);
  }
}
