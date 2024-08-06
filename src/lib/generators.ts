import { encodeBase64urlNoPadding } from "@oslojs/encoding";

export function codeVerifier(): string {
	const randomValues = new Uint8Array(32);
	crypto.getRandomValues(randomValues);
	return encodeBase64urlNoPadding(randomValues);
}

export function state(): string {
	const randomValues = new Uint8Array(32);
	crypto.getRandomValues(randomValues);
	return encodeBase64urlNoPadding(randomValues);
}
