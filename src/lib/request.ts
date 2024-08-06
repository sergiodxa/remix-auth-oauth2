import { encodeBase64 } from "@oslojs/encoding";

export namespace OAuth2Request {
	export class Context {
		public method: string;
		public body = new Map<string, string>();
		public headers = new Map<string, string>();

		constructor(method: string) {
			this.method = method;
			this.headers.set("Content-Type", "application/x-www-form-urlencoded");
			this.headers.set("Accept", "application/json");
			this.headers.set("User-Agent", "oslo");
		}

		public setClientId(clientId: string): void {
			this.body.set("client_id", clientId);
		}

		public authenticateWithRequestBody(
			clientId: string,
			clientSecret: string,
		): void {
			this.setClientId(clientId);
			this.body.set("client_secret", clientSecret);
		}

		public authenticateWithHTTPBasicAuth(
			clientId: string,
			clientSecret: string,
		): void {
			const authorizationHeader = `Basic ${encodeBase64(
				new TextEncoder().encode(`${clientId}:${clientSecret}`),
			)}`;
			this.headers.set("Authorization", authorizationHeader);
		}
	}

	export class Result {
		public body: object;

		constructor(body: object) {
			this.body = body;
		}

		public hasErrorCode(): boolean {
			return "error" in this.body && typeof this.body.error === "string";
		}

		public errorCode(): string {
			if ("error" in this.body && typeof this.body.error === "string") {
				return this.body.error;
			}
			throw new Error("Missing or invalid 'error' field");
		}

		public hasErrorDescription(): boolean {
			return (
				"error_description" in this.body &&
				typeof this.body.error_description === "string"
			);
		}

		public errorDescription(): string {
			if (
				"error_description" in this.body &&
				typeof this.body.error_description === "string"
			) {
				return this.body.error_description;
			}
			throw new Error("Missing or invalid 'error_description' field");
		}

		public hasErrorURI(): boolean {
			return (
				"error_uri" in this.body && typeof this.body.error_uri === "string"
			);
		}

		public errorURI(): string {
			if ("error_uri" in this.body && typeof this.body.error_uri === "string") {
				return this.body.error_uri;
			}
			throw new Error("Missing or invalid 'error_uri' field");
		}

		public state(): string {
			if ("state" in this.body && typeof this.body.state === "string") {
				return this.body.state;
			}
			throw new Error("Missing or invalid 'state' field");
		}
	}
}
