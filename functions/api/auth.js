const SITE_ORIGIN = "https://barrett.rugge.com";

export async function onRequest({ request, env }) {
  if (!env.GITHUB_CLIENT_ID) {
    return new Response("OAuth is not configured", { status: 500 });
  }

  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const state = Array.from(bytes, b =>
    b.toString(16).padStart(2, "0")
  ).join("");

  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", SITE_ORIGIN + "/api/callback");
  authorize.searchParams.set("scope", "repo");
  authorize.searchParams.set("state", state);

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorize.toString(),
      "Set-Cookie": `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=600`,
      "Cache-Control": "no-store"
    }
  });
}
