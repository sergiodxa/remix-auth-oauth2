import { OAuth2RequestContext, OAuth2RequestResult } from "./request.js";

export class DeviceAuthorizationRequestContext extends OAuth2RequestContext {
	constructor() {
		super("POST");
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

export class DeviceAuthorizationTokenRequestContext extends OAuth2RequestContext {
	constructor(deviceCode: string) {
		super("POST");
		this.body.set("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
		this.body.set("device_code", deviceCode);
	}
}

export class DeviceAuthorizationRequestResult extends OAuth2RequestResult {
	public deviceCode(): string {
		if (
			"device_code" in this.body &&
			typeof this.body.device_code === "string"
		) {
			return this.body.device_code;
		}
		throw new Error("Missing or invalid 'device_code' field");
	}

	public userCode(): string {
		if ("user_code" in this.body && typeof this.body.user_code === "string") {
			return this.body.user_code;
		}
		throw new Error("Missing or invalid 'user_code' field");
	}

	public verificationURI(): string {
		if (
			"verification_uri" in this.body &&
			typeof this.body.verification_uri === "string"
		) {
			return this.body.verification_uri;
		}
		throw new Error("Missing or invalid 'verification_uri' field");
	}

	public codesExpireInSeconds(): number {
		if ("expires_in" in this.body && typeof this.body.expires_in === "number") {
			return this.body.expires_in;
		}
		throw new Error("Missing or invalid 'expires_in' field");
	}

	public codesExpireAt(): Date {
		return new Date(Date.now() + this.codesExpireInSeconds() * 1000);
	}

	public intervalSeconds(): number {
		if ("interval" in this.body) {
			if (typeof this.body.interval === "number") {
				return this.body.interval;
			}
			throw new Error("Invalid 'interval' field");
		}
		return 5;
	}
}
