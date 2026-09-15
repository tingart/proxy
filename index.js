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

function id() {
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

function proxyPath(url, sid) {
  return `/proxy/${sid}/${encode(url)}`;
}

/* ---------------- INJECTION ---------------- */

app.post("/inject", (req, res) => {
  const code = req.body?.toString("utf8") || "";

  if (!code) {
    return res.status(400).json({
      error: "No code supplied"
    });
  }

  const injectionId = id();

  injections.set(injectionId, code);

  res.json({
    id: injectionId,
    script: `/inject/${injectionId}.js`
  });
});

app.get("/inject/:id.js", (req, res) => {
  const code = injections.get(req.params.id);

  if (!code) {
    return res.status(404).send("// Injection not found");
  }

  res.type("application/javascript");
  res.send(code);
});

/* ---------------- HTML REWRITE ---------------- */

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

    html = html.replace(regex, (full, start, value, end) => {
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

      return `${start}${proxyPath(url, sid)}${end}`;
    });
  }

  /* srcset */
  html = html.replace(
    /(srcset\s*=\s*[\"'])([^\"']+)([\"'])/gi,
    (full, start, value, end) => {
      const parts = value.split(",");

      const rewritten = parts.map(part => {
        const bits = part.trim().split(/\s+/);

        if (!bits[0]) return part;

        const url = absolute(bits[0], target);

        if (/^https?:\/\//i.test(url)) {
          bits[0] = proxyPath(url, sid);
        }

        return bits.join(" ");
      });

      return start + rewritten.join(", ") + end;
    }
  );

  /* CSS url() */
  html = html.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (full, quote, value) => {
      if (
        value.startsWith("data:") ||
        value.startsWith("blob:") ||
        value.startsWith("#")
      ) {
        return full;
      }

      const url = absolute(value, target);

      if (!/^https?:\/\//i.test(url)) {
        return full;
      }

      return `url("${proxyPath(url, sid)}")`;
    }
  );

  /* Inject our bridge */
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

      const u = new URL(raw, location.href);

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

  const OriginalXHR = XMLHttpRequest;

  window.XMLHttpRequest = function() {
    const xhr = new OriginalXHR();
    const originalOpen = xhr.open;

    xhr.open = function(method, url, ...args) {
      try {
        const u = new URL(url, location.href);

        if (u.origin !== location.origin) {
          url =
            "/__external?url=" +
            encodeURIComponent(u.href);
        }
      } catch {}

      return originalOpen.call(
        xhr,
        method,
        url,
        ...args
      );
    };

    return xhr;
  };
})();
</script>`;

  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(
      /<head[^>]*>/i,
      match => match + bridge
    );
  } else {
    html = bridge + html;
  }

  /* Optional custom injection */
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

/* ---------------- FETCH ---------------- */

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

/* ---------------- PROXY ENGINE ---------------- */

async function handleProxy(req, res, url, sid) {
  try {
    const response =
      await fetchTarget(url, req, sid);

    const session = sessions.get(sid);

    const cookie =
      response.headers.get("set-cookie");

    if (cookie && session) {
      session.cookie = cookie
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
          proxyPath(next, sid)
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

    const buffer = Buffer.from(
      await response.arrayBuffer()
    );

    /* HTML */
    if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml")
    ) {
      const html = rewriteHTML(
        buffer.toString("utf8"),
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

    /* Other files */
    res.status(response.status);

    if (contentType) {
      res.setHeader(
        "Content-Type",
        contentType
      );
    }

    return res.send(buffer);

  } catch (error) {
    console.error(error);

    res.status(502).send(
      "Proxy fetch failed: " +
      error.message
    );
  }
}

/* ---------------- OPEN ---------------- */

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

  const sid = id();

  sessions.set(sid, {
    target,
    cookie: "",
    injection: req.query.inject || null
  });

  res.redirect(
    proxyPath(target, sid)
  );
});

/* ---------------- MAIN PROXY PATH ---------------- */

/*
   /proxy/:sid/:encoded
*/

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
      url = decode(req.params.encoded);
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

/* ---------------- OLD /proxy?url= ---------------- */

/*
   This is kept intentionally so:
   /proxy?url=https://youtube.com
   also works.
*/

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

  if (!sid || !sessions.has(sid)) {
    sid = id();

    sessions.set(sid, {
      target: url,
      cookie: "",
      injection: req.query.inject || null
    });
  }

  await handleProxy(
    req,
    res,
    url,
    sid
  );
});

/* ---------------- EXTERNAL REQUESTS ---------------- */

app.all("/__external", async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res
      .status(400)
      .send("Missing url");
  }

  try {
    const response = await fetch(url, {
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

    const data = Buffer.from(
      await response.arrayBuffer()
    );

    if (type) {
      res.setHeader(
        "Content-Type",
        type
      );
    }

    res.status(response.status);
    res.send(data);

  } catch (error) {
    res.status(502).send(
      "External request failed"
    );
  }
});

/* ---------------- SOURCE ---------------- */

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

  const sid = id();

  sessions.set(sid, {
    target,
    cookie: "",
    injection: req.query.inject || null
  });

  await handleProxy(
    req,
    res,
    target,
    sid
  );
});

/* ---------------- STATUS ---------------- */

app.get("/", (req, res) => {
  res.json({
    name: "Orbit Source Proxy",
    status: "online",
    routes: {
      open: "/open?url=https://example.com",
      proxy: "/proxy?url=https://example.com",
      source: "/source?url=https://example.com",
      inject: "POST /inject"
    }
  });
});

app.listen(PORT, () => {
  console.log(
    `Orbit Source Proxy running on port ${PORT}`
  );
});
