import { OAuth2Request } from "./request.js";

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
