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
export let authenticator = new Authenticator<User>(sessionStorage);

authenticator.use(
	new OAuth2Strategy(
		{
			clientId: CLIENT_ID,
			authorizationEndpoint: "https://provider.com/oauth2/authorize",
			tokenEndpoint: "https://provider.com/oauth2/token",
			redirectURI: "https://example.app/auth/callback",
			scopes: ["openid", "email", "profile"], // optional
			codeChallengeMethod: "S256", // optional
			authenticateWith: "request_body", // optional
			clientSecret: CLIENT_SECRET, // optional
		},
		async ({ tokens, profile, context, request }) => {
			// here you can use the params above to get the user and return it
			// what you do inside this and how you find the user is up to you
			return await getUser(tokens, profile, context, request);
		},
	),
	// this is optional, but if you setup more than one OAuth2 instance you will
	// need to set a custom name to each one
	"provider-name",
);
```

### Using the Refresh Token

The strategy exposes a public `refreshToken` method that you can use to refresh the access token.

```ts
const strategy = new OAuth2Strategy<User>(options, verify);
let tokens = await strategy.refreshToken(refreshToken);
```

How you store the refresh tokens to `strategy.refreshToken` and what you do with the `tokens` object after it is up to you.

### Extending it

You can use this strategy as a base class for another strategy using the OAuth2 framework. That way, you wouldn't need to implement the whole OAuth2 flow yourself.

The `OAuth2Strategy` will handle the whole flow for you and let you replace parts of it where you need.

Let's see how the `Auth0Strategy` is implemented using the `OAuth2Strategy` as a base.

```ts
// We need to import from Remix Auth the type of the strategy verify callback
import type { StrategyVerifyCallback } from "remix-auth";

// We need to import the OAuth2Strategy, the verify params and the profile interfaces
import type {
	OAuth2Profile,
	OAuth2StrategyVerifyParams,
	TokenResponseBody,
} from "remix-auth-oauth2";

import { OAuth2Strategy } from "remix-auth-oauth2";

// These are the custom options we need from the developer to use the strategy
export interface Auth0StrategyOptions
	extends Omit<
		OAuth2StrategyOptions,
		"authorizationEndpoint" | "tokenEndpoint"
	> {
	domain: string;
	audience?: string;
}

// The Auth0Profile extends the OAuth2Profile with the extra params and mark
// some of them as required
export interface Auth0Profile extends OAuth2Profile {
	id: string;
	displayName: string;
	name: {
		familyName: string;
		givenName: string;
		middleName: string;
	};
	emails: Array<{ value: string }>;
	photos: Array<{ value: string }>;
	_json: {
		sub: string;
		name: string;
		given_name: string;
		family_name: string;
		middle_name: string;
		nickname: string;
		preferred_username: string;
		profile: string;
		picture: string;
		website: string;
		email: string;
		email_verified: boolean;
		gender: string;
		birthdate: string;
		zoneinfo: string;
		locale: string;
		phone_number: string;
		phone_number_verified: boolean;
		address: {
			country: string;
		};
		updated_at: string;
	};
}

// And we create our strategy extending the OAuth2Strategy, we also need to
// pass the User as we did on the FormStrategy, we pass the Auth0Profile and the
// extra params
export class Auth0Strategy<User> extends OAuth2Strategy<User, Auth0Profile> {
	// The OAuth2Strategy already has a name but we override it to be specific of
	// the service we are using
	name = "auth0";

	private userInfoURL: string;

	// We receive our custom options and our verify callback
	constructor(
		{ domain, audience, ...options }: Auth0StrategyOptions,
		// Here we type the verify callback as a StrategyVerifyCallback receiving
		// the User type and the OAuth2StrategyVerifyParams with the Auth0Profile.
		verify: StrategyVerifyCallback<
			User,
			OAuth2StrategyVerifyParams<Auth0Profile>
		>,
	) {
		// And we pass the options to the super constructor using our own options
		// to generate them, this was we can ask less configuration to the developer
		// using our strategy
		super(
			{
				authorizationEndpoint: `https://${domain}/authorize`,
				tokenEndpoint: `https://${domain}/oauth/token`,
				...options,
			},
			verify,
		);

		this.userInfoEndpoint = `https://${domain}/userinfo`;
		this.audience = audience;
	}

	// We override the protected authorizationParams method to return a new
	// URLSearchParams with custom params we want to send to the authorizationURL.
	// Here we add the scope so Auth0 can use it, you can pass any extra param
	// you need to send to the authorizationURL here base on your provider.
	protected authorizationParams(params: URLSearchParams) {
		if (this.audience) params.audience = this.audience;
		return params;
	}

	// We also override how to use the accessToken to get the profile of the user.
	// Here we fetch a Auth0 specific URL, get the profile data, and build the
	// object based on the Auth0Profile interface.
	protected async userProfile(
		tokens: TokenResponseBody,
	): Promise<Auth0Profile> {
		let response = await fetch(this.userInfoEndpoint, {
			headers: { Authorization: `Bearer ${tokens.access_token}` },
		});

		let data: Auth0Profile["_json"] = await response.json();

		let profile: Auth0Profile = {
			provider: "auth0",
			displayName: data.name,
			id: data.sub,
			name: {
				familyName: data.family_name,
				givenName: data.given_name,
				middleName: data.middle_name,
			},
			emails: [{ value: data.email }],
			photos: [{ value: data.picture }],
			_json: data,
		};

		return profile;
	}
}
```

And that's it, thanks to the `OAuth2Strategy` we don't need to implement the whole OAuth2 flow ourselves and can focus on the unique parts of our strategy which is the user profile and extra search params our provider may require us to send.
