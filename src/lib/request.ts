import { encodeBase64 } from "@oslojs/encoding";

export namespace OAuth2Request {
	export abstract class Context {
		public method: string;
		public body = new URLSearchParams();
		public headers = new Headers();

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

		toRequest(url: ConstructorParameters<URL>["0"]) {
			return new Request(url, {
				method: this.method,
				body: this.body,
				headers: this.headers,
			});
		}
	}

	// biome-ignore lint/suspicious/noShadowRestrictedNames: It's namespaced
	export class Error extends globalThis.Error {
		public request: Request;
		public context: OAuth2Request.Context;
		public description: string | null;
		public uri: string | null;
		public responseHeaders: Headers;

		constructor(
			message: string,
			request: Request,
			context: OAuth2Request.Context,
			responseHeaders: Headers,
			options?: { description?: string; uri?: string },
		) {
			super(message);
			this.request = request;
			this.context = context;
			this.responseHeaders = responseHeaders;
			this.description = options?.description ?? null;
			this.uri = options?.uri ?? null;
		}
	}
}
