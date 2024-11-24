import { Cookie, SetCookie } from "@mjackson/headers";
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

let debug = createDebug("OAuth2Strategy");

type URLConstructor = ConstructorParameters<typeof URL>[0];

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
			options.redirectURI.toString(),
		);
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

			let header = new SetCookie({
				name: this.options.cookieName ?? "oauth2",
				value: new URLSearchParams({ state, codeVerifier }).toString(),
			});

			throw redirect(url.toString(), {
				headers: { "Set-Cookie": header.toString() },
			});
		}

		let code = url.searchParams.get("code");

		if (!code) throw new ReferenceError("Missing code in the URL");

		let cookie = new Cookie(request.headers.get("cookie") ?? "");
		let params = new URLSearchParams(
			cookie.get(this.options.cookieName ?? "oauth2"),
		);
		if (!params.has("state")) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (params.get("state") !== stateUrl) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		if (!params.has("codeVerifier")) {
			throw new ReferenceError("Missing code verifier on cookie.");
		}

		debug("Validating authorization code");
		let tokens = await this.validateAuthorizationCode(
			code,
			params.get("codeVerifier") as string, // We checked above this is defined
		);

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

	public refreshToken(refreshToken: string) {
		return this.client.refreshAccessToken(
			this.options.tokenEndpoint.toString(),
			refreshToken,
			this.options.scopes ?? [],
		);
	}

	public revokeToken(token: string) {
		let endpoint = this.options.tokenRevocationEndpoint;
		if (!endpoint) throw new Error("Token revocation endpoint is not set.");
		return this.client.revokeToken(endpoint.toString(), token);
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
		cookieName?: string;

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
		 * @default "CodeChallengeMethod.S256"
		 */
		codeChallengeMethod?: CodeChallengeMethod;
	}
}
