import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
import { OAuth2Request } from "./request.js";

export namespace AuthorizationCode {
	export class AuthorizationURL extends URL {
		constructor(authorizationEndpoint: string, clientId: string) {
			super(authorizationEndpoint);
			this.searchParams.set("response_type", "code");
			this.searchParams.set("client_id", clientId);
		}

		public setRedirectURI(redirectURI: string): void {
			this.searchParams.set("redirect_uri", redirectURI);
		}

		public addScopes(...scopes: string[]): void {
			if (scopes.length < 1) {
				return;
			}
			let scopeValue = scopes.join(" ");
			const existingScopes = this.searchParams.get("scope");
			if (existingScopes !== null) {
				scopeValue = ` ${existingScopes}`;
			}
			this.searchParams.set("scope", scopeValue);
		}

		public setState(state: string): void {
			this.searchParams.set("state", state);
		}

		public setS256CodeChallenge(codeVerifier: string): void {
			const codeChallengeBytes = sha256(new TextEncoder().encode(codeVerifier));
			const codeChallenge = encodeBase64urlNoPadding(codeChallengeBytes);
			this.searchParams.set("code_challenge", codeChallenge);
			this.searchParams.set("code_challenge_method", "S256");
		}

		public setPlainCodeChallenge(codeVerifier: string): void {
			this.searchParams.set("code_challenge", codeVerifier);
			this.searchParams.set("code_challenge_method", "plain");
		}
	}

	export class TokenRequestContext extends OAuth2Request.Context {
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
}
