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
import {
	OAuth2Client,
	generateCodeVerifier,
	generateState,
	TokenResponseBody,
} from "oslo/oauth2";

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
	clientId: string;
	authorizationEndpoint: URLConstructor;
	tokenEndpoint: URLConstructor;
	redirectURI: URLConstructor;

	codeChallengeMethod?: "S256" | "plain";
	scopes?: string[];

	authenticateWith?: "http_basic_auth" | "request_body";
	clientSecret?: string;
}

export interface OAuth2StrategyVerifyParams<Profile extends OAuth2Profile> {
	tokens: TokenResponseBody;
	profile: Profile;
	request: Request;
	context?: AppLoadContext;
}

export class OAuth2Strategy<
	User,
	Profile extends OAuth2Profile,
> extends Strategy<User, OAuth2StrategyVerifyParams<Profile>> {
	name = "oauth2";

	protected client: OAuth2Client;

	protected sessionStateKey = "oauth2:state";
	protected sessionCodeVerifierKey = "oauth2:codeVerifier";

	constructor(
		protected options: OAuth2StrategyOptions,
		verify: StrategyVerifyCallback<User, OAuth2StrategyVerifyParams<Profile>>,
	) {
		super(verify);

		this.client = new OAuth2Client(
			options.clientId,
			options.authorizationEndpoint.toString(),
			options.tokenEndpoint.toString(),
			{ redirectURI: options.redirectURI.toString() },
		);
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

		let code = url.searchParams.get("code");

		if (!code) {
			debug("No code found in the URL, redirecting to authorization endpoint");

			let state = generateState();
			session.set(this.sessionStateKey, state);

			debug("State", state);

			let codeVerifier = generateCodeVerifier();
			session.set(this.sessionCodeVerifierKey, codeVerifier);

			debug("Code verifier", codeVerifier);

			let authorizationURL = await this.client.createAuthorizationURL({
				state,
				codeVerifier,
				codeChallengeMethod: this.options.codeChallengeMethod,
				scopes: this.options.scopes,
			});

			// Extend authorization URL with extra non-standard params
			authorizationURL.search = this.authorizationParams(
				authorizationURL.searchParams,
			).toString();

			debug("Authorization URL", authorizationURL.toString());

			throw redirect(authorizationURL.toString(), {
				headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
			});
		}

		let stateUrl = url.searchParams.get("state");
		let codeVerifier = session.get(this.sessionCodeVerifierKey);

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

		try {
			debug("Validating authorization code");
			let tokens = await this.client.validateAuthorizationCode(code, {
				codeVerifier,
				authenticateWith: this.options.authenticateWith,
				credentials: this.options.clientSecret,
			});

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

	protected async userProfile(
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		tokens: TokenResponseBody,
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
	 * Get new tokens using a refresh token.
	 * @param refreshToken The refresh token to use
	 * @param options Optional options to override the default strategy options
	 * @returns A promise that resolves to the new tokens
	 */
	public refreshToken(
		refreshToken: string,
		options: Pick<
			OAuth2StrategyOptions,
			"authenticateWith" | "clientSecret" | "scopes"
		>,
	) {
		return this.client.refreshAccessToken(refreshToken, {
			authenticateWith:
				options.authenticateWith ?? this.options.authenticateWith,
			credentials: options.clientSecret ?? this.options.clientSecret,
			scopes: options.scopes ?? this.options.scopes,
		});
	}
}

export { OAuth2RequestError, TokenResponseBody } from "oslo/oauth2";
