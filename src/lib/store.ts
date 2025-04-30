import { Cookie, SetCookie, type SetCookieInit } from "@mjackson/headers";

/**
 * This class is used to store the state and code verifier for the OAuth2 flow.
 *
 * If the user is redirected to the authorization endpoint, we need to store the
 * state and code verifier in a cookie so we can check that the state matches
 * when the user is redirected back to the application.
 *
 * The problem is that the user can open multiple tabs, and we need to keep
 * track of the state and code verifier for each tab. This class helps us do
 * that.
 *
 * It's a simple class that stores the state in a Set and the code verifier in a
 * Map. The state is used as the key to the code verifier, so we can easily
 * retrieve it when needed. We also have a method to convert the store to a
 * string, so we can store it in a cookie.
 *
 * The class also has a static method to create a new instance from a Request
 * object, this is useful when we need to get the store from the cookie.
 */
export class StateStore {
	states = new Set<string>();
	codeVerifiers = new Map<string, string>();

	state: string | undefined;
	codeVerifier: string | undefined;

	constructor(params = new URLSearchParams()) {
		for (let [state, verifier] of params) {
			if (state === "state") continue;
			this.states.add(state);
			this.codeVerifiers.set(state, verifier);
		}
	}

	/**
	 * Append a new state and code verifier to the store
	 */
	set(state: string, verifier?: string) {
		this.state = state;
		this.codeVerifier = verifier;

		this.states.add(state);
		if (verifier) this.codeVerifiers.set(state, verifier);
	}

	/**
	 * Check if the store has the given state
	 */
	has(state?: string) {
		if (state) return this.states.has(state);
		return this.states.size > 0;
	}

	/**
	 * Get the code verifier for the given state
	 */
	get(state: string) {
		return this.codeVerifiers.get(state);
	}

	/**
	 * Convert the store to a string
	 *
	 * This is useful when we need to store the store in a cookie
	 */
	toString() {
		if (!this.state) return "";
		if (!this.codeVerifier) return "";

		let params = new URLSearchParams();

		params.set("state", this.state);
		params.set(this.state, this.codeVerifier);

		return params.toString();
	}

	toSetCookie(
		cookieName = "oauth2",
		options: Omit<SetCookieInit, "value"> = {},
	) {
		let id = crypto.randomUUID();
		return new SetCookie({
			value: this.toString(),
			httpOnly: true, // Prevents JavaScript from accessing the cookie
			maxAge: 60 * 5, // 5 minutes
			path: "/", // Allow the cookie to be sent to any path
			sameSite: "Lax", // Prevents it from being sent in cross-site requests
			...options,
			name: `${cookieName}:${id}`,
		});
	}

	/**
	 * Create a new instance from a Request object by getting the store from a
	 * cookie with the given name.
	 */
	static fromRequest(request: Request, cookieName = "oauth2") {
		let cookie = new Cookie(request.headers.get("cookie") ?? "");

		let params = new URLSearchParams();

		for (let name of cookie.names) {
			if (name.startsWith(cookieName)) {
				let cookieInstance = cookie.get(name);
				if (!cookieInstance) continue;
				for (let [key, value] of new URLSearchParams(cookieInstance)) {
					params.append(key, value);
				}
			}
		}

		return new StateStore(params);
	}
}
