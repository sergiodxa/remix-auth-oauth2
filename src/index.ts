import { ObjectParser } from "@edgefirst-dev/data/parser";
import { type SetCookieInit } from "@mjackson/headers";
import {
	CodeChallengeMethod,
	OAuth2Client,
	OAuth2RequestError,
	type OAuth2Tokens,
	generateCodeVerifier,
	generateState,
} from "arctic";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";
import { StateStore } from "./lib/store.js";

type URLConstructor = ConstructorParameters<typeof URL>[0];

const debug = createDebug("OAuth2Strategy");

const WELL_KNOWN = ".well-known/openid-configuration";

export { OAuth2RequestError, CodeChallengeMethod };

export class OAuth2Strategy<User> extends Strategy<
	User,
	OAuth2Strategy.VerifyOptions
> {
	override name = "oauth2";

	protected client: OAuth2Client;

	constructor(
		protected options: OAuth2Strategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>,
	) {
		super(verify);

		this.client = new OAuth2Client(
			options.clientId,
			options.clientSecret,
			options.redirectURI?.toString() ?? null,
		);
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || "oauth2";
		}
		return this.options.cookie?.name ?? "oauth2";
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	override async authenticate(request: Request): Promise<User> {
		debug("Request URL", request.url);

		let url = new URL(request.url);

		let stateUrl = url.searchParams.get("state");
		let error = url.searchParams.get("error");

		if (error) {
			let description = url.searchParams.get("error_description");
			let uri = url.searchParams.get("error_uri");
			throw new OAuth2RequestError(error, description, uri, stateUrl);
		}

		if (!stateUrl) {
			debug("No state found in the URL, redirecting to authorization endpoint");

			let { state, codeVerifier, url } = this.createAuthorizationURL();

			debug("State", state);
			debug("Code verifier", codeVerifier);

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

			debug("Authorization URL", url.toString());

			let store = StateStore.fromRequest(request, this.cookieName);
			store.set(state, codeVerifier);

			throw redirect(url.toString(), {
				headers: {
					"Set-Cookie": store
						.toSetCookie(this.cookieName, this.cookieOptions)
						.toString(),
				},
			});
		}

		let code = url.searchParams.get("code");

		if (!code) throw new ReferenceError("Missing code in the URL");

		let store = StateStore.fromRequest(request);

		if (!store.has()) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (!store.has(stateUrl)) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		let codeVerifier = store.get(stateUrl);

		if (!codeVerifier) {
			throw new ReferenceError("Missing code verifier on cookie.");
		}

		debug("Validating authorization code");
		let tokens = await this.validateAuthorizationCode(code, codeVerifier);

		debug("Verifying the user profile");
		let user = await this.verify({ request, tokens });

		debug("User authenticated");
		return user;
	}

	protected createAuthorizationURL() {
		let state = generateState();
		let codeVerifier = generateCodeVerifier();

		let url = this.client.createAuthorizationURLWithPKCE(
			this.options.authorizationEndpoint.toString(),
			state,
			this.options.codeChallengeMethod ?? CodeChallengeMethod.S256,
			codeVerifier,
			this.options.scopes ?? [],
		);

		return { state, codeVerifier, url };
	}

	protected validateAuthorizationCode(code: string, codeVerifier: string) {
		return this.client.validateAuthorizationCode(
			this.options.tokenEndpoint.toString(),
			code,
			codeVerifier,
		);
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
	protected authorizationParams(
		params: URLSearchParams,
		request: Request,
	): URLSearchParams {
		return new URLSearchParams(params);
	}

	/**
	 * Get a new OAuth2 Tokens object using the refresh token once the previous
	 * access token has expired.
	 * @param refreshToken The refresh token to use to get a new access token
	 * @returns The new OAuth2 tokens object
	 * @example
	 * ```ts
	 * let tokens = await strategy.refreshToken(refreshToken);
	 * console.log(tokens.accessToken());
	 * ```
	 */
	public refreshToken(refreshToken: string) {
		return this.client.refreshAccessToken(
			this.options.tokenEndpoint.toString(),
			refreshToken,
			this.options.scopes ?? [],
		);
	}

	/**
	 * Users the token revocation endpoint of the identity provider to revoke the
	 * access token and make it invalid.
	 *
	 * @param token The access token to revoke
	 * @example
	 * ```ts
	 * // Get it from where you stored it
	 * let accessToken = await getAccessToken();
	 * await strategy.revokeToken(tokens.access_token);
	 * ```
	 */
	public revokeToken(token: string) {
		let endpoint = this.options.tokenRevocationEndpoint;
		if (!endpoint) throw new Error("Token revocation endpoint is not set.");
		return this.client.revokeToken(endpoint.toString(), token);
	}

	/**
	 * Discover the OAuth2 issuer and create a new OAuth2Strategy instance from
	 * the OIDC configuration that is returned.
	 *
	 * This method will fetch the OIDC configuration from the issuer and create a
	 * new OAuth2Strategy instance with the provided options and verify function.
	 *
	 * @param uri The URI of the issuer, this can be a full URL or just the domain
	 * @param options The rest of the options to pass to the OAuth2Strategy constructor, clientId, clientSecret, redirectURI, and scopes are required.
	 * @param verify The verify function to use with the OAuth2Strategy instance
	 * @returns A new OAuth2Strategy instance
	 * @example
	 * ```ts
	 * let strategy = await OAuth2Strategy.discover(
	 *   "https://accounts.google.com",
	 *   {
	 *     clientId: "your-client-id",
	 *     clientSecret: "your-client-secret",
	 *     redirectURI: "https://your-app.com/auth/callback",
	 *     scopes: ["openid", "email", "profile"],
	 *   },
	 *   async ({ tokens }) => {
	 *     return getUserProfile(tokens.access_token);
	 *   },
	 * );
	 */
	static async discover<U, M extends OAuth2Strategy<U> = OAuth2Strategy<U>>(
		this: new (
			options: OAuth2Strategy.ConstructorOptions,
			verify: Strategy.VerifyFunction<U, OAuth2Strategy.VerifyOptions>,
		) => M,
		uri: string | URL,
		options: Pick<
			OAuth2Strategy.ConstructorOptions,
			"clientId" | "clientSecret" | "cookie" | "redirectURI" | "scopes"
		> &
			Partial<
				Omit<
					OAuth2Strategy.ConstructorOptions,
					"clientId" | "clientSecret" | "cookie" | "redirectURI" | "scopes"
				>
			>,
		verify: Strategy.VerifyFunction<U, OAuth2Strategy.VerifyOptions>,
	) {
		// Parse the URI into a URL object
		let url = new URL(uri);

		if (!url.pathname.includes("well-known")) {
			// Add the well-known path to the URL if it's not already there
			url.pathname = url.pathname.endsWith("/")
				? `${url.pathname}${WELL_KNOWN}`
				: `${url.pathname}/${WELL_KNOWN}`;
		}

		// Fetch the metadata from the issuer and validate it
		let response = await fetch(url, {
			headers: { Accept: "application/json" },
		});

		// If the response is not OK, throw an error
		if (!response.ok) throw new Error(`Failed to discover issuer at ${url}`);

		// Parse the response body
		let parser = new ObjectParser(await response.json());

		// biome-ignore lint/complexity/noThisInStatic: This is need for subclasses
		return new this(
			{
				authorizationEndpoint: new URL(parser.string("authorization_endpoint")),
				tokenEndpoint: new URL(parser.string("token_endpoint")),
				tokenRevocationEndpoint: parser.has("revocation_endpoint")
					? new URL(parser.string("revocation_endpoint"))
					: undefined,
				codeChallengeMethod: parser.has("code_challenge_methods_supported")
					? parser.array("code_challenge_methods_supported").includes("S256")
						? CodeChallengeMethod.S256
						: CodeChallengeMethod.Plain
					: undefined,
				...options,
			},
			verify,
		);
	}
}

export namespace OAuth2Strategy {
	export interface VerifyOptions {
		/** The request that triggered the verification flow */
		request: Request;
		/** The OAuth2 tokens retrivied from the identity provider */
		tokens: OAuth2Tokens;
	}

	export interface ConstructorOptions {
		/**
		 * The name of the cookie used to keep state and code verifier around.
		 *
		 * The OAuth2 flow requires generating a random state and code verifier, and
		 * then checking that the state matches when the user is redirected back to
		 * the application. This is done to prevent CSRF attacks.
		 *
		 * The state and code verifier are stored in a cookie, and this option
		 * allows you to customize the name of that cookie if needed.
		 * @default "oauth2"
		 */
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });

		/**
		 * This is the Client ID of your application, provided to you by the Identity
		 * Provider you're using to authenticate users.
		 */
		clientId: string;
		/**
		 * This is the Client Secret of your application, provided to you by the
		 * Identity Provider you're using to authenticate users.
		 */
		clientSecret: string | null;

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
		redirectURI: URLConstructor | null;

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
		 * @default "CodeChallengeMethod.S256"
		 */
		codeChallengeMethod?: CodeChallengeMethod;
	}
}
