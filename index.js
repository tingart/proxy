const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.raw({
  type: "*/*",
  limit: "20mb"
}));

const sessions = new Map();
const injections = new Map();

function makeId() {
  return crypto.randomBytes(18).toString("base64url");
}

function encode(url) {
  return Buffer.from(url).toString("base64url");
}

function decode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function absolute(value, base) {
  try {
    return new URL(value, base).href;
  } catch {
    return value;
  }
}

function proxyUrl(url, sid) {
  return `/proxy/${sid}/${encode(url)}`;
}

/* =========================
   CUSTOM INJECTION
========================= */

app.post("/inject", (req, res) => {
  const code = req.body?.toString("utf8") || "";

  if (!code.trim()) {
    return res.status(400).json({
      error: "No code supplied"
    });
  }

  const id = makeId();

  injections.set(id, code);

  res.json({
    id,
    script: `/inject/${id}.js`
  });
});

app.get("/inject/:id.js", (req, res) => {
  const code = injections.get(req.params.id);

  if (!code) {
    return res.status(404).send("// Not found");
  }

  res.setHeader(
    "Content-Type",
    "application/javascript; charset=utf-8"
  );

  res.send(code);
});

/* =========================
   REWRITE HTML
========================= */

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

    const regex = new RegExp(
      `(${attr}\\s*=\\s*[\"'])([^\"']+)([\"'])`,
      "gi"
    );

    html = html.replace(
      regex,
      (full, start, value, end) => {

        if (
          value.startsWith("#") ||
          value.startsWith("javascript:") ||
          value.startsWith("data:") ||
          value.startsWith("blob:") ||
          value.startsWith("mailto:")
        ) {
          return full;
        }

        const url = absolute(value, target);

        if (!/^https?:\/\//i.test(url)) {
          return full;
        }

        return (
          start +
          proxyUrl(url, sid) +
          end
        );
      }
    );
  }

  /* srcset */

  html = html.replace(
    /(srcset\s*=\s*[\"'])([^\"']+)([\"'])/gi,
    (full, start, value, end) => {

      const result = value
        .split(",")
        .map(part => {

          const pieces =
            part.trim().split(/\s+/);

          if (!pieces[0]) return part;

          const url =
            absolute(pieces[0], target);

          if (/^https?:\/\//i.test(url)) {
            pieces[0] =
              proxyUrl(url, sid);
          }

          return pieces.join(" ");
        })
        .join(", ");

      return start + result + end;
    }
  );

  /* CSS url() */

  html = html.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (full, quote, value) => {

      if (
        value.startsWith("data:") ||
        value.startsWith("blob:")
      ) {
        return full;
      }

      const url =
        absolute(value, target);

      if (!/^https?:\/\//i.test(url)) {
        return full;
      }

      return `url("${proxyUrl(url, sid)}")`;
    }
  );

  /* Internal fetch/XHR bridge */

  const bridge = `
<script>
(() => {

  const originalFetch = window.fetch;

  window.fetch = function(input, init) {

    try {

      const raw =
        typeof input === "string"
          ? input
          : input.url;

      const u =
        new URL(raw, location.href);

      if (u.origin === location.origin) {
        return originalFetch(input, init);
      }

      return originalFetch(
        "/__external?url=" +
        encodeURIComponent(u.href),
        init
      );

    } catch {

      return originalFetch(input, init);

    }
  };

})();
</script>
`;

  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(
      /<head[^>]*>/i,
      match => match + bridge
    );
  } else {
    html = bridge + html;
  }

  /* Custom extension */

  const session = sessions.get(sid);

  if (session?.injection) {

    const script = `
<script src="/inject/${session.injection}.js"></script>
`;

    if (/<head[^>]*>/i.test(html)) {
      html = html.replace(
        /<head[^>]*>/i,
        match => match + script
      );
    } else {
      html = script + html;
    }
  }

  return html;
}

/* =========================
   TARGET FETCH
========================= */

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
    headers["content-type"] =
      req.headers["content-type"];
  }

  const options = {
    method: req.method,
    headers,
    redirect: "manual"
  };

  if (
    req.method !== "GET" &&
    req.method !== "HEAD" &&
    req.body?.length
  ) {
    options.body = req.body;
  }

  return fetch(url, options);
}

/* =========================
   PROXY ENGINE
========================= */

async function handleProxy(
  req,
  res,
  url,
  sid
) {

  try {

    const response =
      await fetchTarget(
        url,
        req,
        sid
      );

    const session =
      sessions.get(sid);

    const setCookie =
      response.headers.get("set-cookie");

    if (setCookie && session) {

      session.cookie =
        setCookie
          .split(/,(?=[^;,]+=[^;,]+)/)
          .map(x => x.split(";")[0])
          .join("; ");
    }

    /* Redirect */

    if (
      response.status >= 300 &&
      response.status < 400
    ) {

      const location =
        response.headers.get("location");

      if (location) {

        const next =
          absolute(location, url);

        res.setHeader(
          "Location",
          proxyUrl(next, sid)
        );
      }

      return res
        .status(response.status)
        .end();
    }

    const contentType =
      response.headers.get(
        "content-type"
      ) || "";

    const data = Buffer.from(
      await response.arrayBuffer()
    );

    /* HTML */

    if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml")
    ) {

      const html =
        rewriteHTML(
          data.toString("utf8"),
          url,
          sid
        );

      res.status(response.status);

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      return res.send(html);
    }

    /* Everything else */

    res.status(response.status);

    if (contentType) {
      res.setHeader(
        "Content-Type",
        contentType
      );
    }

    return res.send(data);

  } catch (error) {

    console.error(
      "Proxy error:",
      error
    );

    return res.status(502).send(
      "Proxy fetch failed"
    );
  }
}

/* =========================
   OPEN
========================= */

app.get("/open", (req, res) => {

  const target = req.query.url;

  if (!target) {
    return res
      .status(400)
      .send("Missing url");
  }

  try {
    new URL(target);
  } catch {
    return res
      .status(400)
      .send("Invalid url");
  }

  const sid = makeId();

  sessions.set(sid, {
    target,
    cookie: "",
    injection:
      req.query.inject || null
  });

  res.redirect(
    proxyUrl(target, sid)
  );
});

/* =========================
   SESSION PROXY
========================= */

app.all(
  "/proxy/:sid/:encoded",
  async (req, res) => {

    const sid = req.params.sid;

    if (!sessions.has(sid)) {
      return res
        .status(404)
        .send("Proxy session expired");
    }

    let url;

    try {

      url =
        decode(req.params.encoded);

      new URL(url);

    } catch {

      return res
        .status(400)
        .send("Invalid proxy URL");
    }

    await handleProxy(
      req,
      res,
      url,
      sid
    );
  }
);

/* =========================
   /proxy?url=
========================= */

app.all("/proxy", async (req, res) => {

  const url = req.query.url;

  if (!url) {
    return res
      .status(400)
      .send("Missing url");
  }

  try {
    new URL(url);
  } catch {
    return res
      .status(400)
      .send("Invalid url");
  }

  let sid = req.query.sid;

  if (
    !sid ||
    !sessions.has(sid)
  ) {

    sid = makeId();

    sessions.set(sid, {
      target: url,
      cookie: "",
      injection:
        req.query.inject || null
    });
  }

  await handleProxy(
    req,
    res,
    url,
    sid
  );
});

/* =========================
   /results
   IMPORTANT
========================= */

app.all("/results", async (req, res) => {

  let sid = req.query.sid;

  if (!sid || !sessions.has(sid)) {

    const referer =
      req.headers.referer || "";

    const match =
      referer.match(
        /\/proxy\/([^/]+)\//
      );

    if (match) {
      sid = match[1];
    }
  }

  if (!sid || !sessions.has(sid)) {
    return res
      .status(400)
      .send("Missing proxy session");
  }

  const session =
    sessions.get(sid);

  let target;

  try {

    const base =
      new URL(session.target);

    target =
      new URL(
        "/results" +
        (
          req.originalUrl.includes("?")
            ? req.originalUrl.substring(
                req.originalUrl.indexOf("?")
              )
            : ""
        ),
        base.origin
      ).href;

  } catch {

    return res
      .status(400)
      .send("Invalid target");
  }

  await handleProxy(
    req,
    res,
    target,
    sid
  );
});

/* =========================
   EXTERNAL REQUEST
========================= */

app.all(
  "/__external",
  async (req, res) => {

    const url =
      req.query.url;

    if (!url) {
      return res
        .status(400)
        .send("Missing url");
    }

    try {

      const response =
        await fetch(url, {
          method: req.method,
          headers: {
            "user-agent":
              req.headers["user-agent"] ||
              "Mozilla/5.0",

            "accept":
              req.headers["accept"] ||
              "*/*"
          },
          redirect: "follow"
        });

      const type =
        response.headers.get(
          "content-type"
        );

      const data =
        Buffer.from(
          await response.arrayBuffer()
        );

      if (type) {
        res.setHeader(
          "Content-Type",
          type
        );
      }

      res
        .status(response.status)
        .send(data);

    } catch {

      res
        .status(502)
        .send(
          "External request failed"
        );
    }
  }
);

/* =========================
   SOURCE
========================= */

app.get("/source", async (req, res) => {

  const target = req.query.url;

  if (!target) {
    return res
      .status(400)
      .send("Missing url");
  }

  try {
    new URL(target);
  } catch {
    return res
      .status(400)
      .send("Invalid url");
  }

  const sid = makeId();

  sessions.set(sid, {
    target,
    cookie: "",
    injection:
      req.query.inject || null
  });

  await handleProxy(
    req,
    res,
    target,
    sid
  );
});

/* =========================
   HOME
========================= */

app.get("/", (req, res) => {

  res.json({
    name: "Orbit Source Proxy",
    status: "online",

    routes: {
      open: "/open?url=https://example.com",
      proxy: "/proxy?url=https://example.com",
      results: "/results",
      source: "/source?url=https://example.com",
      inject: "POST /inject"
    }
  });
});

/* =========================
   SERVER
========================= */

app.listen(PORT, () => {
  console.log(
    `Orbit Source Proxy running on port ${PORT}`
  );
});
