import { createCookieSessionStorage, json, redirect } from "@remix-run/node";
import fetchMock, { enableFetchMocks } from "jest-fetch-mock";
import { AuthenticateOptions, AuthorizationError } from "remix-auth";
import {
  OAuth2Profile,
  OAuth2Strategy,
  OAuth2StrategyVerifyParams,
} from "../src";

enableFetchMocks();

const BASE_OPTIONS: AuthenticateOptions = {
  name: "form",
  sessionKey: "user",
  sessionErrorKey: "error",
  sessionStrategyKey: "strategy",
};

describe(OAuth2Strategy, () => {
  let verify = jest.fn();
  let sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });

  let options = Object.freeze({
    authorizationURL: "https://example.app/authorize",
    tokenURL: "https://example.app/token",
    clientID: "MY_CLIENT_ID",
    clientSecret: "MY_CLIENT_SECRET",
    callbackURL: "https://example.com/callback",
  });

  interface User {
    id: string;
  }

  interface TestProfile extends OAuth2Profile {
    provider: "oauth2";
  }

  beforeEach(() => {
    jest.resetAllMocks();
    fetchMock.resetMocks();
  });

  test("should have the name `oauth2`", () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);
    expect(strategy.name).toBe("oauth2");
  });

  test("if user is already in the session redirect to `/`", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("user", { id: "123" });

    let request = new Request("https://example.com/login", {
      headers: { cookie: await sessionStorage.commitSession(session) },
    });

    let user = await strategy.authenticate(
      request,
      sessionStorage,
      BASE_OPTIONS
    );

    expect(user).toEqual({ id: "123" });
  });

  test("if user is already in the session and successRedirect is set throw a redirect", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("user", { id: "123" } as User);

    let request = new Request("https://example.com/login", {
      headers: { cookie: await sessionStorage.commitSession(session) },
    });

    try {
      await strategy.authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        successRedirect: "/dashboard",
      });
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      expect(error.headers.get("Location")).toBe("/dashboard");
    }
  });

  test("should redirect to authorization if request is not the callback", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let request = new Request("https://example.com/login");

    try {
      await strategy.authenticate(request, sessionStorage, BASE_OPTIONS);
    } catch (error) {
      if (!(error instanceof Response)) throw error;

      let redirect = new URL(error.headers.get("Location") as string);

      let session = await sessionStorage.getSession(
        error.headers.get("Set-Cookie")
      );

      expect(error.status).toBe(302);

      expect(redirect.pathname).toBe("/authorize");
      expect(redirect.searchParams.get("response_type")).toBe("code");
      expect(redirect.searchParams.get("client_id")).toBe(options.clientID);
      expect(redirect.searchParams.get("redirect_uri")).toBe(
        options.callbackURL
      );
      expect(redirect.searchParams.has("state")).toBeTruthy();

      expect(session.get("oauth2:state")).toBe(
        redirect.searchParams.get("state")
      );
    }
  });

  test("should throw if state is not on the callback URL params", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);
    let request = new Request("https://example.com/callback");
    let response = json({ message: "Missing state on URL." }, { status: 401 });

    await expect(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS)
    ).rejects.toEqual(response);
  });

  test("should throw if state is not on the session", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);
    let request = new Request("https://example.com/callback?state=value");
    let response = json(
      { message: "Missing state on session." },
      { status: 401 }
    );

    await expect(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS)
    ).rejects.toEqual(response);
  });

  test("should throw if the state in params doesn't match the state in session", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=another-state",
      {
        headers: { cookie: await sessionStorage.commitSession(session) },
      }
    );
    let response = json({ message: "State doesn't match." }, { status: 401 });

    await expect(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS)
    ).rejects.toEqual(response);
  });

  test("should throw if code is not on the callback URL params", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);
    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");
    let request = new Request(
      "https://example.com/callback?state=random-state",
      {
        headers: { cookie: await sessionStorage.commitSession(session) },
      }
    );
    let response = json({ message: "Missing code." }, { status: 401 });

    await expect(
      strategy.authenticate(request, sessionStorage, BASE_OPTIONS)
    ).rejects.toEqual(response);
  });

  test("should call verify with the access token, refresh token, extra params, user profile, context and request", async () => {
    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      {
        headers: { cookie: await sessionStorage.commitSession(session) },
      }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
    );

    let context = { test: "it works" };

    await strategy.authenticate(request, sessionStorage, {
      ...BASE_OPTIONS,
      context,
    });

    let [url, mockRequest] = fetchMock.mock.calls[0];
    let body = mockRequest?.body as URLSearchParams;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let headers = mockRequest?.headers as any;

    expect(url).toBe(options.tokenURL);

    expect(mockRequest?.method as string).toBe("POST");
    expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");

    expect(body.get("client_id")).toBe(options.clientID);
    expect(body.get("client_secret")).toBe(options.clientSecret);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("random-code");

    expect(verify).toHaveBeenLastCalledWith({
      accessToken: "random-access-token",
      refreshToken: "random-refresh-token",
      extraParams: { id_token: "random.id.token" },
      profile: { provider: "oauth2" },
      context,
      request,
    } as OAuth2StrategyVerifyParams<OAuth2Profile, { id_token: string }>);
  });

  test("should return the result of verify", async () => {
    let user = { id: "123" };
    verify.mockResolvedValueOnce(user);

    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      { headers: { cookie: await sessionStorage.commitSession(session) } }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
    );

    let response = await strategy.authenticate(
      request,
      sessionStorage,
      BASE_OPTIONS
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
      }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
    );

    try {
      await strategy.authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        successRedirect: "/",
      });
    } catch (error) {
      if (!(error instanceof Response)) throw error;

      session = await sessionStorage.getSession(
        error.headers.get("Set-Cookie")
      );

      expect(error.headers.get("Location")).toBe("/");
      expect(session.get("user")).toEqual(user);
    }
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
      }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
    );

    let result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError("Invalid credentials"));
    expect((result as AuthorizationError).cause).toEqual(
      new TypeError("Invalid credentials")
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
      }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
    );

    let result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError("Invalid credentials"));
    expect((result as AuthorizationError).cause).toEqual(
      new TypeError("Invalid credentials")
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
      }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
    );

    let result = await strategy
      .authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        throwOnError: true,
      })
      .catch((error) => error);

    expect(result).toEqual(new AuthorizationError("Unknown error"));
    expect((result as AuthorizationError).cause).toEqual(
      new Error(JSON.stringify({ message: "Invalid email address" }, null, 2))
    );
  });

  test("thrown response in verify callback should pass-through", async () => {
    verify.mockRejectedValueOnce(redirect("/test"));

    let strategy = new OAuth2Strategy<User, TestProfile>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      { headers: { cookie: await sessionStorage.commitSession(session) } }
    );

    fetchMock.once(
      JSON.stringify({
        access_token: "random-access-token",
        refresh_token: "random-refresh-token",
        id_token: "random.id.token",
      })
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

  describe("with PKCE enabled", () => {
    test("it should redirect to authorization and establish a challenge", async () => {
      let strategy = new OAuth2Strategy<User, TestProfile>(
        {
          ...options,
          usePKCEFlow: true,
        },
        verify
      );
      let request = new Request("https://example.com/login");
      try {
        await strategy.authenticate(request, sessionStorage, BASE_OPTIONS);
      } catch (error) {
        if (!(error instanceof Response)) throw error;

        let redirect = new URL(error.headers.get("Location") as string);

        let session = await sessionStorage.getSession(
          error.headers.get("Set-Cookie")
        );

        expect(error.status).toBe(302);

        expect(redirect.pathname).toBe("/authorize");
        expect(redirect.searchParams.get("response_type")).toBe("code");
        expect(redirect.searchParams.get("client_id")).toBe(options.clientID);
        expect(redirect.searchParams.get("redirect_uri")).toBe(
          options.callbackURL
        );
        expect(redirect.searchParams.has("state")).toBeTruthy();
        expect(redirect.searchParams.get("code_challenge_method")).toBe("S256");
        expect(redirect.searchParams.has("code_challenge")).toBeTruthy();

        expect(session.get("oauth2:state")).toBe(
          redirect.searchParams.get("state")
        );
      }
    });

    test("it should throw an error if the verifier is not found on the session", async () => {
      let strategy = new OAuth2Strategy<User, TestProfile>(
        {
          ...options,
          usePKCEFlow: true,
        },
        verify
      );
      let session = await sessionStorage.getSession();
      session.set("oauth2:state", "random-state");
      let request = new Request(
        "https://example.com/callback?state=random-state&code=random-code",
        {
          headers: { cookie: await sessionStorage.commitSession(session) },
        }
      );
      let response = json(
        { message: "Missing code verifier on session." },
        { status: 401 }
      );

      await expect(
        strategy.authenticate(request, sessionStorage, BASE_OPTIONS)
      ).rejects.toEqual(response);
    });

    test("should call verify with the access token, refresh token, extra params, user profile, context, and verifier", async () => {
      let strategy = new OAuth2Strategy<User, TestProfile>(
        {
          ...options,
          usePKCEFlow: true,
        },
        verify
      );

      let session = await sessionStorage.getSession();
      session.set("oauth2:state", "random-state");
      session.set("oauth2:code_verifier", "random-verifier");

      let request = new Request(
        "https://example.com/callback?state=random-state&code=random-code",
        {
          headers: { cookie: await sessionStorage.commitSession(session) },
        }
      );

      fetchMock.once(
        JSON.stringify({
          access_token: "random-access-token",
          refresh_token: "random-refresh-token",
          id_token: "random.id.token",
        })
      );

      let context = { test: "it works" };

      await strategy.authenticate(request, sessionStorage, {
        ...BASE_OPTIONS,
        context,
      });

      let [url, mockRequest] = fetchMock.mock.calls[0];
      let body = mockRequest?.body as URLSearchParams;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let headers = mockRequest?.headers as any;

      expect(url).toBe(options.tokenURL);

      expect(mockRequest?.method as string).toBe("POST");
      expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");

      expect(body.get("client_id")).toBe(options.clientID);
      expect(body.get("client_secret")).toBe(options.clientSecret);
      expect(body.get("grant_type")).toBe("authorization_code");
      expect(body.get("code")).toBe("random-code");
      expect(body.get("code_verifier")).toBe("random-verifier");

      expect(verify).toHaveBeenLastCalledWith({
        accessToken: "random-access-token",
        refreshToken: "random-refresh-token",
        extraParams: { id_token: "random.id.token" },
        profile: { provider: "oauth2" },
        context,
        request,
      } as OAuth2StrategyVerifyParams<OAuth2Profile, { id_token: string }>);
    });
  });
});
