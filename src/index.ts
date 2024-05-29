import {
	AuthorizationCodeAccessTokenRequestContext,
	AuthorizationCodeAuthorizationURL,
	OAuth2RequestError,
	RefreshRequestContext,
	TokenResponseBody,
	TokenRevocationRequestContext,
	generateCodeVerifier,
	generateState,
	sendTokenRequest,
	sendTokenRevocationRequest,
} from "@oslojs/oauth2";
import {
	AppLoadContext,
	SessionStorage,
	redirect,
} from "@remix-run/server-runtime";
import createDebug from "debug";
import {
	AuthenticateOptions,
	Strategy,
	StrategyVerifyCallback,
} from "remix-auth";

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

type URLConstructor = ConstructorParameters<typeof URL>[0];

export interface OAuth2StrategyOptions {
	/**
	 * This is the Client ID of your application, provided to you by the Identity
	 * Provider you're using to authenticate users.
	 */
	clientId: string;
	/**
	 * This is the Client Secret of your application, provided to you by the
	 * Identity Provider you're using to authenticate users.
	 */
	clientSecret: string;

	/**
	 * The endpoint the Identity Provider asks you to send users to log in, or
	 * authorize your application.
	 */
	authorizationEndpoint: URLConstructor;
	/**
	 * The endpoint the Identity Provider uses to let's you exchange an access
	 * code for an access and refresh token.
	 */
	tokenEndpoint: URLConstructor;
	/**
	 * The URL of your application where the Identity Provider will redirect the
	 * user after they've logged in or authorized your application.
	 */
	redirectURI: URLConstructor;

	/**
	 * The endpoint the Identity Provider uses to revoke an access or refresh
	 * token, this can be useful to log out the user.
	 */
	tokenRevocationEndpoint?: URLConstructor;

	/**
	 * The scopes you want to request from the Identity Provider, this is a list
	 * of strings that represent the permissions you want to request from the
	 * user.
	 */
	scopes?: string[];

	/**
	 * The code challenge method to use when sending the authorization request.
	 * This is used when the Identity Provider requires a code challenge to be
	 * sent with the authorization request.
	 * @default "S256"
	 */
	codeChallengeMethod?: "S256" | "plain";

	/**
	 * The method to use to authenticate with the Identity Provider, this can be
	 * either `http_basic_auth` or `request_body`.
	 * @default "request_body"
	 */
	authenticateWith?: "http_basic_auth" | "request_body";
}

export interface OAuth2StrategyVerifyParams<
	Profile extends OAuth2Profile,
	ExtraTokenParams extends Record<string, unknown> = Record<string, never>,
> {
	tokens: TokenResponseBody & ExtraTokenParams;
	profile: Profile;
	request: Request;
	context?: AppLoadContext;
}

export class OAuth2Strategy<
	User,
	Profile extends OAuth2Profile,
	ExtraParams extends Record<string, unknown> = Record<string, never>,
> extends Strategy<User, OAuth2StrategyVerifyParams<Profile, ExtraParams>> {
	name = "oauth2";

	protected sessionStateKey = "oauth2:state";
	protected sessionCodeVerifierKey = "oauth2:codeVerifier";
	protected options: OAuth2StrategyOptions;

	constructor(
		options: OAuth2StrategyOptions,
		verify: StrategyVerifyCallback<
			User,
			OAuth2StrategyVerifyParams<Profile, ExtraParams>
		>,
	) {
		super(verify);
		this.options = {
			codeChallengeMethod: "S256",
			authenticateWith: "request_body",
			...options,
		};
	}

	async authenticate(
		request: Request,
		sessionStorage: SessionStorage,
		options: AuthenticateOptions,
	): Promise<User> {
		debug("Request URL", request.url);

		let url = new URL(request.url);

		if (url.searchParams.has("error")) {
			return this.failure(
				"Error on authentication",
				request,
				sessionStorage,
				options,
				new OAuth2Error(request, {
					error: url.searchParams.get("error") ?? undefined,
					error_description:
						url.searchParams.get("error_description") ?? undefined,
					error_uri: url.searchParams.get("error_uri") ?? undefined,
				}),
			);
		}

		let session = await sessionStorage.getSession(
			request.headers.get("Cookie"),
		);

		let stateUrl = url.searchParams.get("state");

		if (!stateUrl) {
			debug("No state found in the URL, redirecting to authorization endpoint");

			let state = generateState();
			session.set(this.sessionStateKey, state);

			debug("State", state);

			let codeVerifier = generateCodeVerifier();
			session.set(this.sessionCodeVerifierKey, codeVerifier);

			debug("Code verifier", codeVerifier);

			let authorizationURL = new AuthorizationCodeAuthorizationURL(
				this.options.authorizationEndpoint.toString(),
				this.options.clientId,
			);

			authorizationURL.setRedirectURI(this.options.redirectURI.toString());
			authorizationURL.setState(state);

			if (this.options.scopes)
				authorizationURL.appendScopes(...this.options.scopes);

			if (this.options.codeChallengeMethod === "S256") {
				authorizationURL.setS256CodeChallenge(codeVerifier);
			} else if (this.options.codeChallengeMethod === "plain") {
				authorizationURL.setPlainCodeChallenge(codeVerifier);
			}

			// Extend authorization URL with extra non-standard params
			authorizationURL.search = this.authorizationParams(
				authorizationURL.searchParams,
			).toString();

			debug("Authorization URL", authorizationURL.toString());

			throw redirect(authorizationURL.toString(), {
				headers: {
					"Set-Cookie": await sessionStorage.commitSession(session),
				},
			});
		}

		let code = url.searchParams.get("code");
		let codeVerifier = session.get(this.sessionCodeVerifierKey);

		if (!code && url.searchParams.has("error")) {
			return this.failure(
				"Error during authentication",
				request,
				sessionStorage,
				options,
				new OAuth2Error(request, {
					error: url.searchParams.get("error") ?? undefined,
					error_description:
						url.searchParams.get("error_description") ?? undefined,
					error_uri: url.searchParams.get("error_uri") ?? undefined,
				}),
			);
		}

		if (!code) {
			return this.failure(
				"Missing code in the URL",
				request,
				sessionStorage,
				options,
				new ReferenceError("Missing code in the URL"),
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
				new ReferenceError("Missing state on session."),
			);
		}

		if (stateSession === stateUrl) {
			debug("State is valid");
			session.unset(this.sessionStateKey);
		} else {
			return await this.failure(
				"State in URL doesn't match state in session.",
				request,
				sessionStorage,
				options,
				new RangeError("State in URL doesn't match state in session."),
			);
		}

		try {
			debug("Validating authorization code");
			let context = new AuthorizationCodeAccessTokenRequestContext(code);

			context.setRedirectURI(this.options.redirectURI.toString());
			context.setCodeVerifier(codeVerifier);

			if (this.options.authenticateWith === "http_basic_auth") {
				context.authenticateWithHTTPBasicAuth(
					this.options.clientId,
					this.options.clientSecret,
				);
			} else if (this.options.authenticateWith === "request_body") {
				context.authenticateWithRequestBody(
					this.options.clientId,
					this.options.clientSecret,
				);
			}

			let tokens = await sendTokenRequest<TokenResponseBody & ExtraParams>(
				this.options.tokenEndpoint.toString(),
				context,
				{ signal: request.signal },
			);

			debug("Fetching the user profile");
			let profile = await this.userProfile(tokens);

			debug("Verifying the user profile");
			let user = await this.verify({
				tokens,
				profile,
				context: options.context,
				request,
			});

			debug("User authenticated");
			return this.success(user, request, sessionStorage, options);
		} catch (error) {
			// Allow responses to pass-through
			if (error instanceof Response) throw error;

			debug("Failed to verify user", error);
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
	}

	protected async userProfile(tokens: TokenResponseBody): Promise<Profile> {
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
	 * Get new tokens using a refresh token.
	 * @param refreshToken The refresh token to use
	 * @param options Optional options to override the default strategy options
	 * @returns A promise that resolves to the new tokens
	 */
	public refreshToken(
		refreshToken: string,
		options: Partial<Pick<OAuth2StrategyOptions, "scopes">> & {
			signal?: AbortSignal;
		} = {},
	) {
		let scopes = options.scopes ?? this.options.scopes ?? [];

		let context = new RefreshRequestContext(refreshToken);

		context.appendScopes(...scopes);

		if (this.options.authenticateWith === "http_basic_auth") {
			context.authenticateWithHTTPBasicAuth(
				this.options.clientId,
				this.options.clientSecret,
			);
		} else if (this.options.authenticateWith === "request_body") {
			context.authenticateWithRequestBody(
				this.options.clientId,
				this.options.clientSecret,
			);
		}

		return sendTokenRequest<TokenResponseBody & ExtraParams>(
			this.options.tokenEndpoint.toString(),
			context,
			{ signal: options.signal },
		);
	}

	public revokeToken(
		accessToken: string,
		options: { signal?: AbortSignal } = {},
	) {
		if (this.options.tokenRevocationEndpoint === undefined) {
			throw new Error("Token revocation endpoint is not set");
		}

		let context = new TokenRevocationRequestContext(accessToken);

		context.setTokenTypeHint("access_token");

		if (this.options.authenticateWith === "http_basic_auth") {
			context.authenticateWithHTTPBasicAuth(
				this.options.clientId,
				this.options.clientSecret,
			);
		} else if (this.options.authenticateWith === "request_body") {
			context.authenticateWithRequestBody(
				this.options.clientId,
				this.options.clientSecret,
			);
		}

		return sendTokenRevocationRequest(
			this.options.tokenEndpoint.toString(),
			context,
			{ signal: options.signal },
		);
	}
}

export interface TokenErrorResponseBody {
	error: string;
	error_description?: string;
	error_uri?: string;
}

export class OAuth2Error extends Error {
	name = "OAuth2Error";

	public request: Request;
	public description: string | null;
	public uri: string | null;

	constructor(request: Request, body: Partial<TokenErrorResponseBody>) {
		super(body.error ?? "");
		this.request = request;
		this.description = body.error_description ?? null;
		this.uri = body.error_uri ?? null;
	}
}

export { OAuth2RequestError };
export type { TokenResponseBody } from "@oslojs/oauth2";
