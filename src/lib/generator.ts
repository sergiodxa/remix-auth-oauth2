/**
 * A lot of the code here was originally implemented by @pilcrowOnPaper for a
 * previous version of `@oslojs/oauth2`, as Pilcrow decided to change the
 * direction of the library to focus on response parsing, I decided to copy the
 * old code and adapt it to the new structure of the library.
 */
import { encodeBase64urlNoPadding } from "@oslojs/encoding";

export namespace Generator {
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
}
