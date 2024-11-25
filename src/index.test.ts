import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	mock,
	test,
} from "bun:test";
import { OAuth2Strategy } from ".";
import { catchResponse } from "./test/helpers";

import { Cookie, SetCookie } from "@mjackson/headers";
import { OAuth2Tokens } from "arctic";
import { redirect } from "./lib/redirect";
import { server } from "./test/mock";

beforeAll(() => {
	server.listen();
});

afterEach(() => {
	server.resetHandlers();
});

afterAll(() => {
	server.close();
});

describe(OAuth2Strategy.name, () => {
	let verify = mock();

	let options = Object.freeze({
		authorizationEndpoint: "https://example.app/authorize",
		tokenEndpoint: "https://example.app/token",
		clientId: "MY_CLIENT_ID",
		clientSecret: "MY_CLIENT_SECRET",
		redirectURI: "https://example.com/callback",
		scopes: ["user:email", "user:profile"],
	} satisfies OAuth2Strategy.ConstructorOptions);

	interface User {
		id: string;
	}

	test("should have the name `oauth2`", () => {
		let strategy = new OAuth2Strategy<User>(options, verify);
		expect(strategy.name).toBe("oauth2");
	});

	test("redirects to authorization url if there's no state", async () => {
		let strategy = new OAuth2Strategy<User>(options, verify);

		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));

		// biome-ignore lint/style/noNonNullAssertion: This is a test
		let redirect = new URL(response.headers.get("location")!);

		let setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");
		let params = new URLSearchParams(setCookie.value);

		expect(redirect.pathname).toBe("/authorize");
		expect(redirect.searchParams.get("response_type")).toBe("code");
		expect(redirect.searchParams.get("client_id")).toBe(options.clientId);
		expect(redirect.searchParams.get("redirect_uri")).toBe(options.redirectURI);
		expect(redirect.searchParams.has("state")).toBeTruthy();
		expect(redirect.searchParams.get("scope")).toBe(options.scopes.join(" "));

		expect(params.get("state")).toBe(redirect.searchParams.get("state"));

		// expect(params.get("codeVerifier")).toBe(
		// 	redirect.searchParams.get("code_challenge"),
		// );

		expect(redirect.searchParams.get("code_challenge_method")).toBe("S256");
	});

	test("throws if there's no state in the session", async () => {
		let strategy = new OAuth2Strategy<User>(options, verify);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
		);

		expect(strategy.authenticate(request)).rejects.toThrowError(
			new ReferenceError("Missing state on cookie."),
		);
	});

	test("throws if the state in the url doesn't match the state in the session", async () => {
		let strategy = new OAuth2Strategy<User>(options, verify);

		let cookie = new Cookie();
		cookie.set(
			"oauth2",
			new URLSearchParams({ state: "random-state" }).toString(),
		);

		let request = new Request(
			"https://example.com/callback?state=another-state&code=random-code",
			{ headers: { Cookie: cookie.toString() } },
		);

		expect(strategy.authenticate(request)).rejects.toThrowError(
			new ReferenceError("State in URL doesn't match state in cookie."),
		);
	});

	test("calls verify with the tokens and request", async () => {
		let strategy = new OAuth2Strategy<User>(options, verify);

		let cookie = new Cookie();
		cookie.set(
			"oauth2",
			new URLSearchParams({
				state: "random-state",
				codeVerifier: "random-code-verifier",
			}).toString(),
		);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{ headers: { cookie: cookie.toString() } },
		);

		await strategy.authenticate(request).catch((error) => error);

		expect(verify).toHaveBeenCalled();
	});

	test("returns the result of verify", () => {
		let user = { id: "123" };
		verify.mockResolvedValueOnce(user);

		let strategy = new OAuth2Strategy<User>(options, verify);

		let cookie = new Cookie();
		cookie.set(
			"oauth2",
			new URLSearchParams({
				state: "random-state",
				codeVerifier: "random-code-verifier",
			}).toString(),
		);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{ headers: { cookie: cookie.toString() } },
		);

		expect(strategy.authenticate(request)).resolves.toEqual(user);
	});
});
