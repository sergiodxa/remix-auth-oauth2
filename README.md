# OAuth2Strategy

A strategy to use and implement OAuth2 framework for authentication with federated services like Google, Facebook, GitHub, etc.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |
| Deno       | ✅          |

## How to use

### Installation

```bash
npm add remix-auth-oauth2
```

### Directly

You can use this strategy by adding it to your authenticator instance and configuring the correct endpoints.

```ts
export let authenticator = new Authenticator<User>();

authenticator.use(
  new OAuth2Strategy(
    {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,

      authorizationEndpoint: "https://provider.com/oauth2/authorize",
      tokenEndpoint: "https://provider.com/oauth2/token",
      redirectURI: "https://example.app/auth/callback",

      tokenRevocationEndpoint: "https://provider.com/oauth2/revoke", // optional

      codeChallengeMethod: "S256", // optional
      scopes: ["openid", "email", "profile"], // optional

      authenticateWith: "request_body", // optional
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

### Using the Refresh Token

The strategy exposes a public `refreshToken` method that you can use to refresh the access token.

```ts
let strategy = new OAuth2Strategy<User>(options, verify);
let tokens = await strategy.refreshToken(refreshToken);
```

The refresh token is part of the `tokens` object the verify function receives. How you store it to call `strategy.refreshToken` and what you do with the `tokens` object after it is up to you.

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

### Revoking tokens

You can revoke the access token the user has with the provider.

```ts
await strategy.revokeToken(user.accessToken);
```
