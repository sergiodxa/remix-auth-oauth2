/**
 * A lot of the code here was originally implemented by @pilcrowOnPaper for a
 * previous version of `@oslojs/oauth2`, as Pilcrow decided to change the
 * direction of the library to focus on response parsing, I decided to copy the
 * old code and adapt it to the new structure of the library.
 */
import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";

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
			if (existingScopes !== null) scopeValue = ` ${existingScopes}`;
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
}
