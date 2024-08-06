import { OAuth2Request } from "./request.js";

export class TokenRequestResult extends OAuth2Request.Result {
	public tokenType(): string {
		if ("token_type" in this.body && typeof this.body.token_type === "string") {
			return this.body.token_type;
		}
		throw new Error("Missing or invalid 'token_type' field");
	}

	public accessToken(): string {
		if (
			"access_token" in this.body &&
			typeof this.body.access_token === "string"
		) {
			return this.body.access_token;
		}
		throw new Error("Missing or invalid 'access_token' field");
	}

	public accessTokenExpiresInSeconds(): number {
		if ("expires_in" in this.body && typeof this.body.expires_in === "number") {
			return this.body.expires_in;
		}
		throw new Error("Missing or invalid 'expires_in' field");
	}

	public accessTokenExpiresAt(): Date {
		return new Date(Date.now() + this.accessTokenExpiresInSeconds() * 1000);
	}

	public hasRefreshToken(): boolean {
		return (
			"refresh_token" in this.body &&
			typeof this.body.refresh_token === "string"
		);
	}

	public refreshToken(): string {
		if (
			"refresh_token" in this.body &&
			typeof this.body.refresh_token === "string"
		) {
			return this.body.refresh_token;
		}
		throw new Error("Missing or invalid 'refresh_token' field");
	}

	public refreshTokenExpiresInSeconds(): number {
		if (
			"refresh_token_expires_in" in this.body &&
			typeof this.body.refresh_token_expires_in === "number"
		) {
			return this.body.refresh_token_expires_in;
		}
		throw new Error("Missing or invalid 'refresh_token_expires_in' field");
	}

	public refreshTokenExpiresAt(): Date {
		return new Date(Date.now() + this.refreshTokenExpiresInSeconds() * 1000);
	}
}
