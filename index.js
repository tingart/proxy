const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.raw({
  type: "*/*",
  limit: "20mb"
}));

const sessions = new Map();

function token() {
  return crypto.randomBytes(18).toString("base64url");
}

function absoluteUrl(value, base) {
  try {
    return new URL(value, base).href;
  } catch {
    return value;
  }
}

function proxyUrl(url, sid) {
  return `/p/${sid}/${Buffer.from(url).toString("base64url")}`;
}

function rewriteHTML(html, target, sid) {
  const attrs = [
    "href",
    "src",
    "action",
    "poster",
    "data-src",
    "data-href",
    "formaction"
  ];

  for (const attr of attrs) {
    const re = new RegExp(
      `(${attr}\\s*=\\s*[\"'])([^\"']+)([\"'])`,
      "gi"
    );

    html = html.replace(re, (full, a, value, c) => {
      if (
        value.startsWith("#") ||
        value.startsWith("javascript:") ||
        value.startsWith("data:") ||
        value.startsWith("mailto:")
      ) return full;

      const u = absoluteUrl(value, target);
      return `${a}${proxyUrl(u, sid)}${c}`;
    });
  }

  html = html.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (full, q, value) => {
      if (
        value.startsWith("data:") ||
        value.startsWith("#")
      ) return full;

      const u = absoluteUrl(value, target);
      return `url("${proxyUrl(u, sid)}")`;
    }
  );

  const bridge = `
<script>
(() => {
  const originalFetch = window.fetch;

  window.fetch = function(input, init) {
    try {
      const raw = typeof input === "string"
        ? input
        : input.url;

      const u = new URL(raw, location.href);

      if (u.origin === location.origin) {
        return originalFetch(input, init);
      }

      return originalFetch(
        ${JSON.stringify("/__external?url=")} +
        encodeURIComponent(u.href),
        init
      );
    } catch {
      return originalFetch(input, init);
    }
  };
})();
</script>`;

  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(/<head[^>]*>/i, m => m + bridge);
  } else {
    html = bridge + html;
  }

  return html;
}

async function fetchTarget(url, req, sid) {
  const session = sessions.get(sid);

  const headers = {
    "user-agent":
      req.headers["user-agent"] ||
      "Mozilla/5.0",
    "accept":
      req.headers["accept"] ||
      "*/*",
    "accept-language":
      req.headers["accept-language"] ||
      "en-US,en;q=0.9"
  };

  if (session?.cookie) {
    headers.cookie = session.cookie;
  }

  if (req.headers["content-type"]) {
    headers["content-type"] = req.headers["content-type"];
  }

  const init = {
    method: req.method,
    headers,
    redirect: "manual"
  };

  if (
    req.method !== "GET" &&
    req.method !== "HEAD" &&
    req.body?.length
  ) {
    init.body = req.body;
  }

  return fetch(url, init);
}

async function handleProxy(req, res, url, sid) {
  try {
    const response = await fetchTarget(url, req, sid);

    const setCookie = response.headers.get("set-cookie");
    if (setCookie) {
      sessions.get(sid).cookie = setCookie
        .split(/,(?=[^;,]+=[^;,]+)/)
        .map(x => x.split(";")[0])
        .join("; ");
    }

    if (
      response.status >= 300 &&
      response.status < 400
    ) {
      const location = response.headers.get("location");

      if (location) {
        const next = absoluteUrl(location, url);
        res.setHeader(
          "Location",
          proxyUrl(next, sid)
        );
      }

      return res.status(response.status).end();
    }

    const contentType =
      response.headers.get("content-type") || "";

    const buffer = Buffer.from(
      await response.arrayBuffer()
    );

    if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml")
    ) {
      let html = buffer.toString("utf8");
      html = rewriteHTML(html, url, sid);

      res.status(response.status);
      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      return res.send(html);
    }

    res.status(response.status);

    if (contentType) {
      res.setHeader("Content-Type", contentType);
    }

    const length = response.headers.get("content-length");
    if (length) {
      res.setHeader("Content-Length", length);
    }

    return res.send(buffer);

  } catch (err) {
    console.error(err);
    res.status(502).send("Proxy fetch failed");
  }
}

/* Start a proxy session */
app.get("/open", (req, res) => {
  const target = req.query.url;

  if (!target) {
    return res.status(400).send("Missing url");
  }

  try {
    new URL(target);
  } catch {
    return res.status(400).send("Invalid url");
  }

  const sid = token();

  sessions.set(sid, {
    target,
    cookie: ""
  });

  res.redirect(proxyUrl(target, sid));
});

/* Main proxy route */
app.all("/p/:sid/:encoded", async (req, res) => {
  const { sid, encoded } = req.params;

  if (!sessions.has(sid)) {
    return res.status(404).send("Session expired");
  }

  let url;

  try {
    url = Buffer.from(encoded, "base64url").toString("utf8");
    new URL(url);
  } catch {
    return res.status(400).send("Invalid proxy URL");
  }

  await handleProxy(req, res, url, sid);
});

/* External fetch bridge */
app.all("/__external", async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).send("Missing url");
  }

  try {
    const u = new URL(url);

    const response = await fetch(u.href, {
      method: req.method,
      headers: {
        "user-agent":
          req.headers["user-agent"] ||
          "Mozilla/5.0",
        "accept":
          req.headers["accept"] ||
          "*/*"
      }
    });

    const type =
      response.headers.get("content-type");

    const data = Buffer.from(
      await response.arrayBuffer()
    );

    if (type) res.setHeader("Content-Type", type);

    res.status(response.status).send(data);

  } catch {
    res.status(502).send("External fetch failed");
  }
});

/* Source endpoint */
app.get("/source", async (req, res) => {
  const target = req.query.url;

  if (!target) {
    return res.status(400).send("Missing url");
  }

  try {
    new URL(target);
  } catch {
    return res.status(400).send("Invalid url");
  }

  const sid = token();

  sessions.set(sid, {
    target,
    cookie: ""
  });

  const response = await fetchTarget(
    target,
    req,
    sid
  );

  const type =
    response.headers.get("content-type") || "";

  const data = Buffer.from(
    await response.arrayBuffer()
  );

  if (type.includes("text/html")) {
    const html = rewriteHTML(
      data.toString("utf8"),
      target,
      sid
    );

    return res.type("html").send(html);
  }

  res.setHeader("Content-Type", type);
  res.send(data);
});

app.get("/", (req, res) => {
  res.json({
    name: "Orbit Source Proxy",
    status: "online",
    usage: "/open?url=https://example.com"
  });
});

app.listen(PORT, () => {
  console.log(`Proxy running on ${PORT}`);
});
