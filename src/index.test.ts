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

import { SetCookie } from "@mjackson/headers";
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

		let response = await catchResponse(strategy.authenticate(request));

		expect(response.status).toBe(401);
		await expect(response.json()).resolves.toEqual({
			message: "Missing state on session.",
		});
	});

	test("throws if the state in the url doesn't match the state in the session", async () => {
		let strategy = new OAuth2Strategy<User>(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=another-state&code=random-code",
			{ headers: { cookie: await sessionStorage.commitSession(session) } },
		);

		let response = await catchResponse(strategy.authenticate(request));

		expect(response.status).toBe(401);

		let data = await response.json();

		expect(data).toEqual({
			message: "State in URL doesn't match state in session.",
		});
	});

	// test.skip("calls verify with the tokens and request", async () => {
	// 	let strategy = new OAuth2Strategy<User>(options, verify);

	// 	let session = await sessionStorage.getSession();
	// 	session.set("oauth2:state", "random-state");

	// 	let request = new Request(
	// 		"https://example.com/callback?state=random-state&code=random-code",
	// 		{
	// 			headers: { cookie: await sessionStorage.commitSession(session) },
	// 		},
	// 	);

	// 	let context = { test: "it works" };
	// 	await strategy.authenticate(request).catch((error) => error);

	// 	expect(verify).toHaveBeenLastCalledWith({
	// 		tokens: {
	// 			access_token: "mocked",
	// 			expires_in: 3600,
	// 			refresh_token: "mocked",
	// 			scope: "user:email user:profile",
	// 			token_type: "Bearer",
	// 		},
	// 		request,
	// 	} satisfies OAuth2Strategy.VerifyOptions);
	// });

	test("returns the result of verify", async () => {
		let user = { id: "123" };
		verify.mockResolvedValueOnce(user);

		let strategy = new OAuth2Strategy<User>(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{ headers: { cookie: await sessionStorage.commitSession(session) } },
		);

		let response = await strategy.authenticate(request);

		expect(response).toEqual(user);
	});

	test("throws a response with user in session and redirect to /", async () => {
		let user = { id: "123" };
		verify.mockResolvedValueOnce(user);

		let strategy = new OAuth2Strategy<User>(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{
				headers: { cookie: await sessionStorage.commitSession(session) },
			},
		);

		let response = await catchResponse(strategy.authenticate(request));

		session = await sessionStorage.getSession(
			response.headers.get("Set-Cookie"),
		);

		expect(response.headers.get("Location")).toBe("/");
		expect(session.get("user")).toEqual(user);
	});

	test("pass error as cause on failure", async () => {
		verify.mockRejectedValueOnce(new TypeError("Invalid credentials"));

		let strategy = new OAuth2Strategy(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{
				headers: { cookie: await sessionStorage.commitSession(session) },
			},
		);

		let result = await strategy.authenticate(request).catch((error) => error);

		expect(result).toEqual(new Error("Invalid credentials"));
		expect((result as Error).cause).toEqual(
			new TypeError("Invalid credentials"),
		);
	});

	test("pass generate error from string on failure", async () => {
		verify.mockRejectedValueOnce("Invalid credentials");

		let strategy = new OAuth2Strategy(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{
				headers: { cookie: await sessionStorage.commitSession(session) },
			},
		);

		let result = await strategy.authenticate(request).catch((error) => error);

		expect(result).toEqual(new Error("Invalid credentials"));
		expect((result as Error).cause).toEqual(new Error("Invalid credentials"));
	});

	test("creates Unknown error if thrown value is not Error or string", async () => {
		verify.mockRejectedValueOnce({ message: "Invalid email address" });

		let strategy = new OAuth2Strategy(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{
				headers: { cookie: await sessionStorage.commitSession(session) },
			},
		);

		let result = await strategy.authenticate(request).catch((error) => error);

		expect(result).toEqual(new Error("Unknown error"));
		expect((result as Error).cause).toEqual(
			new Error(JSON.stringify({ message: "Invalid email address" }, null, 2)),
		);
	});

	test("thrown response in verify callback should pass-through", async () => {
		verify.mockRejectedValueOnce(redirect("/test"));

		let strategy = new OAuth2Strategy<User>(options, verify);

		let session = await sessionStorage.getSession();
		session.set("oauth2:state", "random-state");

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{ headers: { cookie: await sessionStorage.commitSession(session) } },
		);

		let response = await strategy
			.authenticate(request)
			.then(() => {
				throw new Error("Should have failed.");
			})
			.catch((error: unknown) => {
				if (error instanceof Response) return error;
				throw error;
			});

		expect(response.status).toEqual(302);
		expect(response.headers.get("location")).toEqual("/test");
	});

	// test.skip("throws if there's an error in the url", async () => {
	// 	let strategy = new OAuth2Strategy<User>(options, verify);

	// 	let request = new Request(
	// 		"https://example.com/callback?error=invalid_request",
	// 	);

	// 	expect(() => strategy.authenticate(request)).toThrowError(
	// 		// @ts-expect-error - This is a test
	// 		new AuthorizationError("Error on authentication", {
	// 			cause: new OAuth2Error(request, {
	// 				error: "invalid_request",
	// 				error_description: undefined,
	// 			}),
	// 		}),
	// 	);
	// });
});
