import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	mock,
	test,
} from "bun:test";
import { Cookie, SetCookie } from "@mjackson/headers";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { Authenticator } from "remix-auth";
import { OAuth2Strategy } from ".";
import { catchResponse } from "./test/helpers";

const server = setupServer(
	http.post("https://example.app/token", async () => {
		return HttpResponse.json({
			access_token: "mocked",
			expires_in: 3600,
			refresh_token: "mocked",
			scope: ["user:email", "user:profile"].join(" "),
			token_type: "Bearer",
		});
	}),
);

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

	beforeAll(() => {
		server.listen();
	});

	afterEach(() => {
		server.resetHandlers();
	});

	afterAll(() => {
		server.close();
	});

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

		await strategy.authenticate(request);

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

	test("discovers provider configuration", async () => {
		let handler = mock().mockImplementationOnce(() =>
			HttpResponse.json({
				authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
				token_endpoint: "https://oauth2.googleapis.com/token",
				revocation_endpoint: "https://oauth2.googleapis.com/revoke",
				code_challenge_methods_supported: ["plain", "S256"],
			}),
		);

		server.use(
			http.get(
				"https://accounts.google.com/.well-known/openid-configuration",
				handler,
			),
		);

		await OAuth2Strategy.discover(
			"https://accounts.google.com",
			{
				clientId: options.clientId,
				clientSecret: options.clientSecret,
				redirectURI: options.redirectURI,
				scopes: options.scopes,
			},
			verify,
		);

		expect(handler).toHaveBeenCalledTimes(1);
	});
});
