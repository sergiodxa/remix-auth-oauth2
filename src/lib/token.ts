/**
 * A lot of the code here was originally implemented by @pilcrowOnPaper for a
 * previous version of `@oslojs/oauth2`, as Pilcrow decided to change the
 * direction of the library to focus on response parsing, I decided to copy the
 * old code and adapt it to the new structure of the library.
 */
import { OAuth2RequestResult, TokenRequestResult } from "@oslojs/oauth2";
import { OAuth2Request } from "./request.js";

type URLConstructor = ConstructorParameters<typeof URL>[0];

export namespace Token {
	export namespace Response {
		export interface Body {
			access_token: string;
			token_type: string;
			expires_in?: number;
			refresh_token?: string;
			scope?: string;
		}

		export interface ErrorBody {
			error: string;
			error_description?: string;
		}
	}

	export namespace Request {
		export class Context extends OAuth2Request.Context {
			constructor(authorizationCode: string) {
				super("POST");
				this.body.set("grant_type", "authorization_code");
				this.body.set("code", authorizationCode);
			}

			public setCodeVerifier(codeVerifier: string): void {
				this.body.set("code_verifier", codeVerifier);
			}

			public setRedirectURI(redirectURI: string): void {
				this.body.set("redirect_uri", redirectURI);
			}
		}

		export async function send<ExtraParams extends Record<string, unknown>>(
			endpoint: URLConstructor,
			context: OAuth2Request.Context,
			options?: { signal?: AbortSignal },
		): Promise<Response.Body & ExtraParams> {
			let request = context.toRequest(endpoint);
			let response = await fetch(request, { signal: options?.signal });
			let body = await response.json();

			let result = new Result<ExtraParams>(body);

			if (result.hasErrorCode()) {
				throw new OAuth2Request.Error(
					result.errorCode(),
					request,
					context,
					response.headers,
					{
						description: result.hasErrorDescription()
							? result.errorDescription()
							: undefined,
						uri: result.hasErrorURI() ? result.errorURI() : undefined,
					},
				);
			}

			return result.toJSON();
		}

		export class Result<
			ExtraParams extends Record<string, unknown>,
		> extends TokenRequestResult {
			// Make token type optional
			override tokenType() {
				if (
					"token_type" in this.body &&
					typeof this.body.token_type === "string"
				) {
					return this.body.token_type;
				}
				return "unknown";
			}
			toJSON(): Response.Body & ExtraParams {
				return {
					...this.body,
					access_token: this.accessToken(),
					token_type: this.tokenType(),
					...("expires_in" in this.body && {
						expires_in: this.accessTokenExpiresInSeconds(),
					}),
					...(this.hasScopes() && { scope: this.scopes().join(" ") }),
					...(this.hasRefreshToken() && { refresh_token: this.refreshToken() }),
				} as Response.Body & ExtraParams;
			}
		}
	}

	export namespace RevocationRequest {
		export class Context extends OAuth2Request.Context {
			constructor(token: string) {
				super("POST");
				this.body.set("token", token);
			}

			public setTokenTypeHint(
				tokenType: "access_token" | "refresh_token",
			): void {
				if (tokenType === "access_token") {
					this.body.set("token_type_hint", "access_token");
				} else if (tokenType === "refresh_token") {
					this.body.set("token_type_hint", "refresh_token");
				}
			}
		}

		export async function send(
			endpoint: URLConstructor,
			context: OAuth2Request.Context,
			options?: { signal?: AbortSignal },
		) {
			let request = context.toRequest(endpoint);
			let response = await fetch(request, { signal: options?.signal });
			let body = await response.json();

			let result = new OAuth2RequestResult(body);

			if (result.hasErrorCode()) {
				throw new OAuth2Request.Error(
					result.errorCode(),
					request,
					context,
					response.headers,
					{
						description: result.hasErrorDescription()
							? result.errorDescription()
							: undefined,
						uri: result.hasErrorURI() ? result.errorURI() : undefined,
					},
				);
			}
		}
	}

	export namespace RefreshRequest {
		export class Context extends OAuth2Request.Context {
			constructor(refreshToken: string) {
				super("POST");
				this.body.set("grant_type", "refresh_token");
				this.body.set("refresh_token", refreshToken);
			}

			public addScopes(...scopes: string[]): void {
				if (scopes.length < 1) {
					return;
				}
				let scopeValue = scopes.join(" ");
				const existingScopes = this.body.get("scope");
				if (existingScopes !== null) {
					scopeValue = `${scopeValue} ${existingScopes}`;
				}
				this.body.set("scope", scopeValue);
			}
		}
	}
}
