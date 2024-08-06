import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

export const server = setupServer(
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
