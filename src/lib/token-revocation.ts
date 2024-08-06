import { OAuth2Request } from "./request.js";

export type TokenType = "access_token" | "refresh_token";

export namespace TokenRevocationRequest {
	export class Context extends OAuth2Request.Context {
		constructor(token: string) {
			super("POST");
			this.body.set("token", token);
		}

		public setTokenTypeHint(tokenType: TokenType): void {
			if (tokenType === "access_token") {
				this.body.set("token_type_hint", "access_token");
			} else if (tokenType === "refresh_token") {
				this.body.set("token_type_hint", "refresh_token");
			}
		}
	}
}
