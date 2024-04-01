import { createCookieSessionStorage, redirect } from "@remix-run/node";
import { vi, describe, test, expect } from "vitest";
import { AuthenticateOptions, AuthorizationError } from "remix-auth";
import {
  OAuth2Profile,
  OAuth2Strategy,
  OAuth2StrategyOptions,
  OAuth2StrategyVerifyParams,
} from "../build";
import { catchResponse } from "./helpers";

const BASE_OPTIONS: AuthenticateOptions = {
  name: "form",
  sessionKey: "user",
  sessionErrorKey: "error",
  sessionStrategyKey: "strategy",
};

describe(OAuth2Strategy, () => {
  let verify = vi.fn();
  let sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });

  let options = Object.freeze({
    authorizationEndpoint: "https://example.app/authorize",
    tokenEndpoint: "https://example.app/token",
    clientId: "MY_CLIENT_ID",
    clientSecret: "MY_CLIENT_SECRET",
    redirectURI: "https://example.com/callback",
    scopes: ["user:email", "user:profile"],
    codeChallengeMethod: "plain",
  } satisfies OAuth2StrategyOptions);

  interface User {
    id: string;
  }

  interface TestProfile extends OAuth2Profile {
    provider: "oauth2";
  }

  test("should have the name `oauth2`", () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);
    expect(strategy.name).toBe("oauth2");
  });

  test("redirects to authorization url if there's no code", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let request = new Request("https://remix.auth/login");

    let response = await catchResponse(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS),
    );

    let redirect = new URL(response.headers.get("location")!);

    let session = await sessionStorage.getSession(
      response.headers.get("set-cookie"),
    );

    expect(response.status).toBe(302);

    expect(redirect.pathname).toBe("/authorize");
    expect(redirect.searchParams.get("response_type")).toBe("code");
    expect(redirect.searchParams.get("client_id")).toBe(options.clientId);
    expect(redirect.searchParams.get("redirect_uri")).toBe(options.redirectURI);
    expect(redirect.searchParams.has("state")).toBeTruthy();
    expect(redirect.searchParams.get("scope")).toBe(options.scopes.join(" "));

    expect(session.get("oauth2:state")).toBe(
      redirect.searchParams.get("state"),
    );

    expect(session.get("oauth2:codeVerifier")).toBe(
      redirect.searchParams.get("code_challenge"),
    );

    expect(redirect.searchParams.get("code_challenge_method")).toBe("plain");
  });

  test("throws if there's no state in the url", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let request = new Request("https://example.com/callback?code=random-code");

    let response = await catchResponse(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS),
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      message: "Missing state on URL.",
    });
  });

  test("throws if there's no state in the session", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
    );

    let response = await catchResponse(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS),
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      message: "Missing state on session.",
    });
  });

  test("throws if the state in the url doesn't match the state in the session", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=another-state&code=random-code",
      { headers: { cookie: await sessionStorage.commitSession(session) } },
    );

    let response = await catchResponse(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS),
    );

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      message: "State doesn't match.",
    });
  });

  test("should call verify with the tokens, user profile, context and request", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      {
        headers: { cookie: await sessionStorage.commitSession(session) },
      },
    );

    let context = { test: "it works" };

    await strategy.authenticate(request, sessionStorage, {
      ...BASE_OPTIONS,
      context,
    });

    expect(verify).toHaveBeenLastCalledWith({
      tokens: {
        access_token: "mocked",
        expires_in: 3600,
        refresh_token: "mocked",
        scope: "user:email user:profile",
        token_type: "Bearer",
      },
      profile: { provider: "oauth2" },
      context,
      request,
    } satisfies OAuth2StrategyVerifyParams<OAuth2Profile>);
  });

  test("should return the result of verify", async () => {
    let user = { id: "123" };
    verify.mockResolvedValueOnce(user);

    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      { headers: { cookie: await sessionStorage.commitSession(session) } },
    );

    let response = await strategy.authenticate(
      request,
      sessionStorage,
      BASE_OPTIONS,
    );

    expect(response).toEqual(user);
  });

  test("should throw a response with user in session and redirect to /", async () => {
    let user = { id: "123" };
    verify.mockResolvedValueOnce(user);

    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      {
        headers: { cookie: await sessionStorage.commitSession(session) },
      },
    );

    let response = await catchResponse(
      strategy.authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        successRedirect: "/",
      }),
    );

    session = await sessionStorage.getSession(
      response.headers.get("Set-Cookie"),
    );

    expect(response.headers.get("Location")).toBe("/");
    expect(session.get("user")).toEqual(user);
  });

  test("should pass error as cause on failure", async () => {
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

    let result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError("Invalid credentials"));
    expect((result as AuthorizationError).cause).toEqual(
      new TypeError("Invalid credentials"),
    );
  });

  test("should pass generate error from string on failure", async () => {
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

    let result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError("Invalid credentials"));
    expect((result as AuthorizationError).cause).toEqual(
      new TypeError("Invalid credentials"),
    );
  });

  test("should create Unknown error if thrown value is not Error or string", async () => {
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

    let result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError("Unknown error"));
    expect((result as AuthorizationError).cause).toEqual(
      new Error(JSON.stringify({ message: "Invalid email address" }, null, 2)),
    );
  });

  test("thrown response in verify callback should pass-through", async () => {
    verify.mockRejectedValueOnce(redirect("/test"));

    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      { headers: { cookie: await sessionStorage.commitSession(session) } },
    );

    let response = await strategy
      .authenticate(request, sessionStorage, BASE_OPTIONS)
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
});
