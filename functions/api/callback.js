const SITE_ORIGIN = "https://barrett-rugge-com.pages.dev";

function popupResponse(status, content, httpStatus = 200) {
  const message = `authorization:github:${status}:${JSON.stringify(content)}`;

  // Safely embed the message in an HTML script.
  const safeMessage = JSON.stringify(message).replace(/</g, "\\u003c");
  const safeOrigin = JSON.stringify(SITE_ORIGIN);

  const html = `<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script>
(function () {
  const origin = ${safeOrigin};
  const message = ${safeMessage};

  if (!window.opener) {
    document.body.textContent = "Please return to the editor and try again.";
    return;
  }

  function receiveMessage(event) {
    if (event.origin !== origin || event.source !== window.opener) {
      return;
    }
    window.removeEventListener("message", receiveMessage);
    window.opener.postMessage(message, origin);
  }

  window.addEventListener("message", receiveMessage);
  window.opener.postMessage("authorizing:github", origin);
})();
</script>
</body>
</html>`;

  return new Response(html, {
    status: httpStatus,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy":
        "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
      "Set-Cookie":
        "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=0"
    }
  });
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const part of cookies.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const savedState = getCookie(request, "oauth_state");

  if (!state || !savedState || state !== savedState) {
    return popupResponse("error", {
      message: "Invalid or expired login session. Please try again."
    }, 400);
  }

  if (!code) {
    return popupResponse("error", {
      message: "GitHub authorization was cancelled or denied."
    }, 400);
  }

  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return popupResponse("error", {
      message: "OAuth credentials are not configured."
    }, 500);
  }

  try {
    const response = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "User-Agent": "barrett-article-editor"
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: SITE_ORIGIN + "/api/callback"
        })
      }
    );

    if (!response.ok) {
      throw new Error("GitHub token exchange failed");
    }

    const result = await response.json();

    if (result.error || !result.access_token) {
      return popupResponse("error", {
        message: result.error_description || "GitHub authorization failed."
      }, 401);
    }

    return popupResponse("success", {
      token: result.access_token,
      provider: "github"
    });
  } catch (error) {
    console.error("OAuth callback failed:", error);
    return popupResponse("error", {
      message: "Unable to complete GitHub login."
    }, 500);
  }
}
