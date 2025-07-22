# OAuth2Strategy

A strategy to use and implement OAuth2 framework for authentication with federated services like Google, Facebook, GitHub, etc.

> [!WARNING]
> This strategy expects the identity provider to strictly follow the OAuth2 specification. If the provider does not follow the specification and diverges from it, this strategy may not work as expected.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## How to use

### Installation

```bash
npm add remix-auth-oauth2
```

### Directly

You can use this strategy by adding it to your authenticator instance and configuring the correct endpoints.

```ts
import { OAuth2Strategy, CodeChallengeMethod } from "remix-auth-oauth2";

export const authenticator = new Authenticator<User>();

authenticator.use(
  new OAuth2Strategy(
    {
      cookie: "oauth2", // Optional, can also be an object with more options

      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,

      authorizationEndpoint: "https://provider.com/oauth2/authorize",
      tokenEndpoint: "https://provider.com/oauth2/token",
      redirectURI: "https://example.app/auth/callback",

      tokenRevocationEndpoint: "https://provider.com/oauth2/revoke", // optional

      scopes: ["openid", "email", "profile"], // optional
      codeChallengeMethod: CodeChallengeMethod.S256, // optional
      additionalParams: {
        access_type: "offline",
        duration: "permanent",
      }, // optional
    },
    async ({ tokens, request }) => {
      // here you can use the params above to get the user and return it
      // what you do inside this and how you find the user is up to you
      return await getUser(tokens, request);
    }
  ),
  // this is optional, but if you setup more than one OAuth2 instance you will
  // need to set a custom name to each one
  "provider-name"
);
```

Then you will need to setup your routes, for the OAuth2 flows you will need to call the `authenticate` method twice.

First, you will call the `authenticate` method with the provider name you set in the authenticator.

```ts
export async function action({ request }: Route.ActionArgs) {
  await authenticator.authenticate("provider-name", request);
}
```

> [!NOTE]
> This route can be an `action` or a `loader`, it depends if you trigger the flow doing a POST or GET request.

This will start the OAuth2 flow and redirect the user to the provider's login page. Once the user logs in and authorizes your application, the provider will redirect the user back to your application redirect URI.

You will now need a route on that URI to handle the callback from the provider.

```ts
export async function loader({ request }: Route.LoaderArgs) {
  let user = await authenticator.authenticate("provider-name", request);
  // now you have the user object with the data you returned in the verify function
}
```

> [!NOTE]
> This route must be a `loader` as the redirect will trigger a `GET` request.

Once you have the `user` object returned by your strategy verify function, you can do whatever you want with that information. This can be storing the user in a session, creating a new user in your database, link the account to an existing user in your database, etc.

### Using the Refresh Token

The strategy exposes a public `refreshToken` method that you can use to refresh the access token.

```ts
let strategy = new OAuth2Strategy<User>(options, verify);
let tokens = await strategy.refreshToken(refreshToken);
```

The refresh token is part of the `tokens` object the verify function receives. How you store it to call `strategy.refreshToken` and what you do with the `tokens` object after it is up to you.

### Additional Parameters

You can pass additional parameters to the authorization request using the `additionalParams` option. This is useful for provider-specific parameters or custom requirements.

```ts
let strategy = new OAuth2Strategy(
  {
    // ... other options
    additionalParams: {
      access_type: "offline",        // Request refresh token
      prompt: "consent",             // Force consent screen
      duration: "temporary", // Reddit-like access duration
    },
  },
  verify
);
```

Common use cases:
- **Google OAuth2**: Use `access_type: "offline"` to request refresh tokens
- **Reddit OAuth2**: Use `duration: "permanent"` to handle token duration
- **Custom providers**: Add any provider-specific parameters

The most common approach would be to store the refresh token in the user data and then update the session after refreshing the token.

```ts
authenticator.use(
  new OAuth2Strategy<User>(
    options,
    async ({ tokens, request }) => {
      let user = await getUser(tokens, request);
      return {
        ...user,
        accessToken: tokens.accessToken()
        refreshToken: tokens.hasRefreshToken() ? tokens.refreshToken() : null,
      }
    }
  )
);

// later in your code you can use it to get new tokens object
let tokens = await strategy.refreshToken(user.refreshToken);
```

### Revoking Tokens

You can revoke the access token the user has with the provider.

```ts
await strategy.revokeToken(user.accessToken);
```

### Discovering the Provider

If you want to discover the provider's endpoints, you can use the `discover` static method.

```ts
export let authenticator = new Authenticator<User>();

authenticator.use(
  await OAuth2Strategy.discover<User>(
    "https://provider.com",
    {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectURI: "https://example.app/auth/callback",
      scopes: ["openid", "email", "profile"], // optional
    },
    async ({ tokens, request }) => {
      // here you can use the params above to get the user and return it
      // what you do inside this and how you find the user is up to you
      return await getUser(tokens, request);
    }
  )
);
```

This will fetch the provider's configuration endpoint (`/.well-known/openid-configuration`) and grab the authorization, token and revocation endpoints from it, it will also grab the code challenge method supported and try to use S256 if it is supported.

Remember this will do a fetch when then strategy is created, this will add a latency to the startup of your application.

It's recommended to use this method only once and then copy the endpoints to your configuration.

### Customizing the Cookie

You can customize the cookie options by passing an object to the `cookie` option.

```ts
authenticator.use(
  new OAuth2Strategy<User>(
    {
      cookie: {
        name: "oauth2",
        maxAge: 60 * 60 * 24 * 7, // 1 week
        path: "/auth",
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      },
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorizationEndpoint: "https://provider.com/oauth2/authorize",
      tokenEndpoint: "https://provider.com/oauth2/token",
      redirectURI: "https://example.app/auth/callback",
    },
    async ({ tokens, request }) => {
      return await getUser(tokens, request);
    }
  )
);
```

This will set the cookie with the name `oauth2`, with a max age of 1 week, only accessible on the `/auth` path, http only, same site lax and secure if the application is running in production.
