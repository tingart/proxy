const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   BODY
========================================================= */

app.use(express.raw({
  type: "*/*",
  limit: "20mb"
}));

/* =========================================================
   STORAGE
========================================================= */

const sessions = new Map();
const injections = new Map();

/*
 * Session:
 *
 * {
 *   target,
 *   created,
 *   cookies: Map(origin -> Map(cookieName -> cookieValue)),
 *   injection,
 *   budgetDay,
 *   usedMs,
 *   lastNavigationAt
 * }
 */

/* =========================================================
   LIMITS
========================================================= */

const DAILY_LIMIT_MS = 10 * 60 * 1000;
const NAVIGATION_COOLDOWN_MS = 4000;

const SESSION_TTL_MS = 6 * 60 * 60 * 1000;
const INJECTION_TTL_MS = 60 * 60 * 1000;

const MAX_INJECTION_BYTES = 2 * 1024 * 1024;

/* =========================================================
   ID / ENCODING
========================================================= */

function makeId() {
  return crypto.randomBytes(24).toString("base64url");
}

function encode(value) {
  return Buffer.from(String(value), "utf8").toString("base64url");
}

function decode(value) {
  return Buffer.from(String(value), "base64url").toString("utf8");
}

/* =========================================================
   URL HELPERS
========================================================= */

function isHttpUrl(value) {
  try {
    const url = new URL(value);

    return (
      url.protocol === "http:" ||
      url.protocol === "https:"
    );
  } catch {
    return false;
  }
}

function absolute(value, base) {
  try {
    return new URL(value, base).href;
  } catch {
    return null;
  }
}

function proxyUrl(url, sid) {
  return `/proxy/${encodeURIComponent(sid)}/${encode(url)}`;
}

function shouldSkipUrl(value) {
  const v = String(value || "")
    .trim()
    .toLowerCase();

  return (
    !v ||
    v.startsWith("#") ||
    v.startsWith("javascript:") ||
    v.startsWith("data:") ||
    v.startsWith("blob:") ||
    v.startsWith("mailto:") ||
    v.startsWith("tel:") ||
    v.startsWith("about:") ||
    v.startsWith("chrome:") ||
    v.startsWith("file:")
  );
}

/* =========================================================
   COOKIE / SESSION
========================================================= */

function getCookie(req, name) {
  const header = req.headers.cookie || "";

  const escaped = name.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );

  const match = header.match(
    new RegExp(
      "(?:^|;\\s*)" +
      escaped +
      "=([^;]*)"
    )
  );

  return match
    ? decodeURIComponent(match[1])
    : null;
}

function setSessionCookie(res, sid) {
  res.setHeader(
    "Set-Cookie",
    `orbit_sid=${encodeURIComponent(
      sid
    )}; Path=/; HttpOnly; SameSite=Lax`
  );
}

function createSession(target, injection = null) {
  const sid = makeId();

  sessions.set(sid, {
    target,
    created: Date.now(),

    cookies: new Map(),

    injection:
      typeof injection === "string" &&
      injection.trim()
        ? injection
        : null,

    budgetDay: Date.now(),
    usedMs: 0,

    lastNavigationAt: 0
  });

  return sid;
}

function getSession(req, sid = null) {
  if (
    sid &&
    sessions.has(sid)
  ) {
    return {
      sid,
      session: sessions.get(sid)
    };
  }

  const cookieSid =
    getCookie(req, "orbit_sid");

  if (
    cookieSid &&
    sessions.has(cookieSid)
  ) {
    return {
      sid: cookieSid,
      session: sessions.get(cookieSid)
    };
  }

  return null;
}

/* =========================================================
   DAILY TIME LIMIT
========================================================= */

function resetBudgetIfNeeded(session) {
  const now = Date.now();

  if (
    !session.budgetDay ||
    now - session.budgetDay >= 24 * 60 * 60 * 1000
  ) {
    session.budgetDay = now;
    session.usedMs = 0;
  }
}

function remainingBudget(session) {
  resetBudgetIfNeeded(session);

  return Math.max(
    0,
    DAILY_LIMIT_MS - session.usedMs
  );
}

function isNavigationRequest(req) {
  if (
    req.method !== "GET" &&
    req.method !== "HEAD"
  ) {
    return false;
  }

  const accept =
    String(req.headers.accept || "")
      .toLowerCase();

  const secFetchDest =
    String(
      req.headers["sec-fetch-dest"] || ""
    ).toLowerCase();

  return (
    secFetchDest === "document" ||
    accept.includes("text/html") ||
    req.path === "/open"
  );
}

function navigationAllowed(session) {
  resetBudgetIfNeeded(session);

  if (remainingBudget(session) <= 0) {
    return {
      ok: false,
      reason: "daily-limit"
    };
  }

  const now = Date.now();

  if (
    session.lastNavigationAt &&
    now - session.lastNavigationAt <
      NAVIGATION_COOLDOWN_MS
  ) {
    return {
      ok: false,
      reason: "cooldown",
      retryAfter:
        NAVIGATION_COOLDOWN_MS -
        (now - session.lastNavigationAt)
    };
  }

  return {
    ok: true
  };
}

function chargeNavigation(session, elapsed) {
  resetBudgetIfNeeded(session);

  session.usedMs += Math.max(
    0,
    elapsed
  );

  session.lastNavigationAt =
    Date.now();
}

/* =========================================================
   COOKIE JAR
========================================================= */

function getCookieJar(session, targetUrl) {
  const origin =
    new URL(targetUrl).origin;

  let jar =
    session.cookies.get(origin);

  if (!jar) {
    jar = new Map();

    session.cookies.set(
      origin,
      jar
    );
  }

  return jar;
}

function cookieHeader(session, targetUrl) {
  const origin =
    new URL(targetUrl).origin;

  const jar =
    session.cookies.get(origin);

  if (!jar || jar.size === 0) {
    return "";
  }

  return [...jar.entries()]
    .map(
      ([name, value]) =>
        `${name}=${value}`
    )
    .join("; ");
}

/*
 * We intentionally keep the cookie jar isolated by target origin.
 * Target cookies are never sent to another session.
 */
function saveCookies(
  response,
  session,
  targetUrl
) {
  if (!session) {
    return;
  }

  let setCookies = [];

  if (
    typeof response.headers.getSetCookie ===
    "function"
  ) {
    setCookies =
      response.headers.getSetCookie();
  } else {
    const single =
      response.headers.get(
        "set-cookie"
      );

    if (single) {
      setCookies = [single];
    }
  }

  if (!setCookies.length) {
    return;
  }

  const jar =
    getCookieJar(
      session,
      targetUrl
    );

  for (const raw of setCookies) {
    const first =
      String(raw).split(";")[0];

    const index =
      first.indexOf("=");

    if (index <= 0) {
      continue;
    }

    const name =
      first
        .slice(0, index)
        .trim();

    const value =
      first
        .slice(index + 1)
        .trim();

    if (!name) {
      continue;
    }

    /*
     * Basic deletion handling.
     */
    const lower =
      String(raw).toLowerCase();

    if (
      lower.includes(
        "max-age=0"
      ) ||
      lower.includes(
        "expires=thu, 01 jan 1970"
      )
    ) {
      jar.delete(name);
    } else {
      jar.set(
        name,
        value
      );
    }
  }
}

/* =========================================================
   REQUEST HEADERS
========================================================= */

function buildTargetHeaders(
  req,
  targetUrl
) {
  const headers = {
    "user-agent":
      req.headers["user-agent"] ||
      "Mozilla/5.0",

    "accept":
      req.headers.accept ||
      "*/*",

    "accept-language":
      req.headers["accept-language"] ||
      "en-US,en;q=0.9"
  };

  /*
   * Forward useful request headers,
   * but do not forward hop-by-hop headers.
   */
  const allowed = [
    "content-type",
    "content-length",
    "range",

    "if-none-match",
    "if-modified-since",

    "cache-control",
    "pragma",

    "origin",
    "referer",

    "accept-encoding"
  ];

  for (const name of allowed) {
    if (req.headers[name]) {
      headers[name] =
        req.headers[name];
    }
  }

  return headers;
}

/* =========================================================
   TARGET FETCH
========================================================= */

async function fetchTarget(
  url,
  req,
  sid
) {
  const session =
    sessions.get(sid);

  const headers =
    buildTargetHeaders(
      req,
      url
    );

  if (session) {
    const cookies =
      cookieHeader(
        session,
        url
      );

    if (cookies) {
      headers.cookie =
        cookies;
    }
  }

  const options = {
    method: req.method,
    headers,

    /*
     * Manual redirect is required so we can
     * rewrite Location back into Orbit proxy URLs.
     */
    redirect: "manual"
  };

  if (
    req.method !== "GET" &&
    req.method !== "HEAD" &&
    req.body &&
    req.body.length
  ) {
    options.body = req.body;
  }

  return fetch(
    url,
    options
  );
}

/* =========================================================
   RESPONSE HEADERS
========================================================= */

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",

  /*
   * These can become invalid after fetch/decompression
   * or HTML rewriting.
   */
  "content-length",
  "content-encoding",

  /*
   * Never expose target cookies.
   */
  "set-cookie"
]);

function copyResponseHeaders(
  response,
  res
) {
  for (const [
    name,
    value
  ] of response.headers) {
    const lower =
      name.toLowerCase();

    if (
      HOP_BY_HOP_HEADERS.has(
        lower
      )
    ) {
      continue;
    }

    res.setHeader(
      name,
      value
    );
  }
}

/* =========================================================
   STREAM RESPONSE
========================================================= */

async function streamResponse(
  response,
  res
) {
  if (
    response.body &&
    typeof response.body.getReader ===
      "function"
  ) {
    const reader =
      response.body.getReader();

    try {
      while (true) {
        const {
          done,
          value
        } = await reader.read();

        if (done) {
          break;
        }

        if (
          !res.write(
            Buffer.from(value)
          )
        ) {
          await new Promise(
            resolve =>
              res.once(
                "drain",
                resolve
              )
          );
        }
      }

      res.end();
      return;
    } catch (error) {
      try {
        res.destroy(error);
      } catch {}

      return;
    }
  }

  const buffer =
    Buffer.from(
      await response.arrayBuffer()
    );

  res.send(buffer);
}

/* =========================================================
   HTML URL REWRITER
========================================================= */

function rewriteHTML(
  html,
  target,
  sid
) {
  /*
   * Normal URL attributes.
   */
  const attrs = [
    "href",
    "src",
    "action",
    "poster",

    "data-src",
    "data-href",
    "data-url",
    "data-action",

    "formaction"
  ];

  for (const attr of attrs) {
    const regex =
      new RegExp(
        `(${attr}\\s*=\\s*[\"'])([^\"']+)([\"'])`,
        "gi"
      );

    html =
      html.replace(
        regex,
        (
          full,
          start,
          value,
          end
        ) => {
          if (
            shouldSkipUrl(value)
          ) {
            return full;
          }

          const url =
            absolute(
              value,
              target
            );

          if (
            !url ||
            !isHttpUrl(url)
          ) {
            return full;
          }

          return (
            start +
            proxyUrl(
              url,
              sid
            ) +
            end
          );
        }
      );
  }

  /* =====================================================
     SRCSET
  ===================================================== */

  html =
    html.replace(
      /(srcset\s*=\s*[\"'])([^\"']+)([\"'])/gi,
      (
        full,
        start,
        value,
        end
      ) => {
        const result =
          value
            .split(",")
            .map(part => {
              const pieces =
                part
                  .trim()
                  .split(/\s+/);

              if (!pieces[0]) {
                return part;
              }

              const url =
                absolute(
                  pieces[0],
                  target
                );

              if (
                url &&
                isHttpUrl(url)
              ) {
                pieces[0] =
                  proxyUrl(
                    url,
                    sid
                  );
              }

              return pieces.join(
                " "
              );
            })
            .join(", ");

        return (
          start +
          result +
          end
        );
      }
    );

  /* =====================================================
     CSS url()
  ===================================================== */

  html =
    html.replace(
      /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
      (
        full,
        quote,
        value
      ) => {
        if (
          shouldSkipUrl(value)
        ) {
          return full;
        }

        const url =
          absolute(
            value,
            target
          );

        if (
          !url ||
          !isHttpUrl(url)
        ) {
          return full;
        }

        return (
          `url("${proxyUrl(
            url,
            sid
          )}")`
        );
      }
    );

  /* =====================================================
     META REFRESH
  ===================================================== */

  html =
    html.replace(
      /(<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["'][^"']*\burl=)([^"']+)(["'])/gi,
      (
        full,
        start,
        value,
        end
      ) => {
        const url =
          absolute(
            value.trim(),
            target
          );

        if (
          !url ||
          !isHttpUrl(url)
        ) {
          return full;
        }

        return (
          start +
          proxyUrl(
            url,
            sid
          ) +
          end
        );
      }
    );

  /* =====================================================
     ORBIT BROWSER BRIDGE
  ===================================================== */

  const session =
    sessions.get(sid);

  const injectionId =
    session?.injection ||
    null;

  const bridge = `
<script>
(() => {
  "use strict";

  const ORBIT_SID =
    ${JSON.stringify(sid)};

  const ORBIT_TARGET =
    ${JSON.stringify(target)};

  const CACHE_NAME =
    "orbit-cache-" +
    ORBIT_SID;

  const EXTENSION_KEY =
    "orbit-extension-" +
    ORBIT_SID;

  const nativeFetch =
    window.fetch.bind(window);

  const NativeXHR =
    window.XMLHttpRequest;

  function resolveTargetUrl(value) {
    try {
      return new URL(
        typeof value === "string"
          ? value
          : value.url,
        ORBIT_TARGET
      ).href;
    } catch {
      return null;
    }
  }

  function proxyUrlForTarget(url) {
    const bytes =
      new TextEncoder()
        .encode(url);

    let binary = "";

    for (
      let i = 0;
      i < bytes.length;
      i++
    ) {
      binary += String.fromCharCode(
        bytes[i]
      );
    }

    const encoded =
      btoa(binary)
        .replace(/=+$/g, "")
        .replace(/\\+/g, "-")
        .replace(/\\//g, "_");

    return (
      "/proxy/" +
      encodeURIComponent(
        ORBIT_SID
      ) +
      "/" +
      encoded
    );
  }

  function isOrbitUrl(url) {
    try {
      return (
        new URL(
          url,
          location.href
        ).origin ===
        location.origin
      );
    } catch {
      return false;
    }
  }

  async function putCache(
    requestUrl,
    response
  ) {
    try {
      const cache =
        await caches.open(
          CACHE_NAME
        );

      await cache.put(
        requestUrl,
        response.clone()
      );
    } catch {}
  }

  async function cacheFirst(
    requestUrl,
    init
  ) {
    try {
      const cache =
        await caches.open(
          CACHE_NAME
        );

      const cached =
        await cache.match(
          requestUrl
        );

      if (cached) {
        return cached;
      }

      const response =
        await nativeFetch(
          requestUrl,
          init
        );

      if (
        response &&
        response.ok
      ) {
        await putCache(
          requestUrl,
          response
        );
      }

      return response;
    } catch {
      return nativeFetch(
        requestUrl,
        init
      );
    }
  }

  /* =====================================================
     ORBIT SOURCE API

     Orbit itself can use:
       await window.OrbitSource.read(url)
       await window.OrbitSource.files()
       await window.OrbitSource.save(url)
  ===================================================== */

  window.OrbitSource = {

    sid:
      ORBIT_SID,

    target:
      ORBIT_TARGET,

    async read(url) {
      const targetUrl =
        resolveTargetUrl(
          url
        );

      if (!targetUrl) {
        throw new Error(
          "Invalid URL"
        );
      }

      const cache =
        await caches.open(
          CACHE_NAME
        );

      /*
       * First look for the actual
       * target URL.
       */
      let response =
        await cache.match(
          targetUrl
        );

      /*
       * Then look for its proxy URL.
       */
      if (!response) {
        const proxy =
          proxyUrlForTarget(
            targetUrl
          );

        response =
          await cache.match(
            proxy
          );
      }

      /*
       * Resource wasn't cached.
       * Server becomes the fallback.
       */
      if (!response) {
        response =
          await cacheFirst(
            proxyUrlForTarget(
              targetUrl
            )
          );
      }

      return response.text();
    },

    async get(url) {
      return this.read(url);
    },

    async files() {
      const cache =
        await caches.open(
          CACHE_NAME
        );

      const requests =
        await cache.keys();

      return requests.map(
        request =>
          request.url
      );
    },

    async save(url) {
      const text =
        await this.read(url);

      const blob =
        new Blob(
          [text],
          {
            type:
              "text/plain;charset=utf-8"
          }
        );

      return URL.createObjectURL(
        blob
      );
    },

    async clear() {
      await caches.delete(
        CACHE_NAME
      );
    }
  };

  /* =====================================================
     LOCAL EXTENSION STORE
  ===================================================== */

  window.OrbitExtension = {

    set(code) {
      if (
        typeof code !==
        "string"
      ) {
        throw new TypeError(
          "Extension code must be a string"
        );
      }

      localStorage.setItem(
        EXTENSION_KEY,
        code
      );

      return true;
    },

    get() {
      return (
        localStorage.getItem(
          EXTENSION_KEY
        ) || ""
      );
    },

    clear() {
      localStorage.removeItem(
        EXTENSION_KEY
      );
    }
  };

  /* =====================================================
     FETCH BRIDGE
  ===================================================== */

  window.fetch =
    async function(
      input,
      init
    ) {
      const targetUrl =
        resolveTargetUrl(
          input
        );

      if (!targetUrl) {
        return nativeFetch(
          input,
          init
        );
      }

      /*
       * Every request from the
       * target page goes through
       * this session.
       */
      const proxy =
        proxyUrlForTarget(
          targetUrl
        );

      return cacheFirst(
        proxy,
        init
      );
    };

  /* =====================================================
     XHR BRIDGE
  ===================================================== */

  function OrbitXHR() {
    const xhr =
      new NativeXHR();

    const nativeOpen =
      xhr.open.bind(xhr);

    xhr.open =
      function(
        method,
        url,
        ...args
      ) {
        try {
          const targetUrl =
            resolveTargetUrl(
              url
            );

          if (targetUrl) {
            url =
              proxyUrlForTarget(
                targetUrl
              );
          }
        } catch {}

        return nativeOpen(
          method,
          url,
          ...args
        );
      };

    return xhr;
  }

  window.XMLHttpRequest =
    OrbitXHR;

  /* =====================================================
     AUTO EXTENSION
  ===================================================== */

  async function runExtension() {
    const code =
      localStorage.getItem(
        EXTENSION_KEY
      );

    if (!code) {
      return;
    }

    try {
      const fn =
        new Function(
          "window",
          "document",
          "location",
          code
        );

      await fn(
        window,
        document,
        location
      );
    } catch (error) {
      console.error(
        "[Orbit Extension]",
        error
      );
    }
  }

  if (
    document.readyState ===
    "loading"
  ) {
    document.addEventListener(
      "DOMContentLoaded",
      runExtension,
      { once: true }
    );
  } else {
    runExtension();
  }

  /* =====================================================
     SPA HISTORY
  ===================================================== */

  for (
    const method of [
      "pushState",
      "replaceState"
    ]
  ) {
    const original =
      history[method];

    history[method] =
      function() {
        const result =
          original.apply(
            this,
            arguments
          );

        setTimeout(
          runExtension,
          0
        );

        return result;
      };
  }

  window.addEventListener(
    "popstate",
    () => {
      setTimeout(
        runExtension,
        0
      );
    }
  );

})();
</script>
`;

  if (
    /<head[^>]*>/i.test(html)
  ) {
    html =
      html.replace(
        /<head[^>]*>/i,
        match =>
          match + bridge
      );
  } else {
    html =
      bridge + html;
  }

  /* =====================================================
     SERVER INJECTION COMPATIBILITY
  ===================================================== */

  if (injectionId) {
    const script = `
<script
  src="/inject/${encodeURIComponent(
    injectionId
  )}.js"
  data-orbit-injection="server">
</script>
`;

    if (
      /<head[^>]*>/i.test(html)
    ) {
      html =
        html.replace(
          /<head[^>]*>/i,
          match =>
            match + script
        );
    } else {
      html =
        script + html;
    }
  }

  return html;
}

/* =========================================================
   PROXY ENGINE
========================================================= */

async function handleProxy(
  req,
  res,
  url,
  sid
) {
  const session =
    sessions.get(sid);

  if (!session) {
    return res
      .status(404)
      .send(
        "Proxy session expired"
      );
  }

  if (!isHttpUrl(url)) {
    return res
      .status(400)
      .send(
        "Only HTTP(S) URLs are supported"
      );
  }

  const navigation =
    isNavigationRequest(req);

  if (navigation) {
    const gate =
      navigationAllowed(
        session
      );

    if (!gate.ok) {
      if (
        gate.reason ===
        "daily-limit"
      ) {
        return res
          .status(429)
          .json({
            error:
              "Daily proxy time limit reached",

            dailyLimitSeconds:
              DAILY_LIMIT_MS / 1000,

            usedSeconds:
              Math.ceil(
                session.usedMs /
                1000
              ),

            remainingSeconds:
              Math.floor(
                remainingBudget(
                  session
                ) / 1000
              )
          });
      }

      res.setHeader(
        "Retry-After",
        Math.ceil(
          gate.retryAfter /
          1000
        )
      );

      return res
        .status(429)
        .json({
          error:
            "Navigation cooldown",

          retryAfterMs:
            gate.retryAfter
        });
    }
  }

  const started =
    Date.now();

  try {
    const response =
      await fetchTarget(
        url,
        req,
        sid
      );

    saveCookies(
      response,
      session,
      url
    );

    /*
     * Navigation time is counted
     * after upstream response arrives.
     */
    if (navigation) {
      chargeNavigation(
        session,
        Date.now() - started
      );
    }

    setSessionCookie(
      res,
      sid
    );

    /* =====================================================
       REDIRECT
    ===================================================== */

    if (
      response.status >= 300 &&
      response.status < 400
    ) {
      const location =
        response.headers.get(
          "location"
        );

      if (location) {
        const next =
          absolute(
            location,
            url
          );

        if (
          next &&
          isHttpUrl(next)
        ) {
          res.setHeader(
            "Location",
            proxyUrl(
              next,
              sid
            )
          );
        }
      }

      return res
        .status(
          response.status
        )
        .end();
    }

    const contentType =
      response.headers.get(
        "content-type"
      ) || "";

    /* =====================================================
       HTML
    ===================================================== */

    if (
      contentType
        .toLowerCase()
        .includes(
          "text/html"
        ) ||
      contentType
        .toLowerCase()
        .includes(
          "application/xhtml"
        )
    ) {
      const data =
        Buffer.from(
          await response.arrayBuffer()
        );

      const html =
        rewriteHTML(
          data.toString(
            "utf8"
          ),
          url,
          sid
        );

      res.status(
        response.status
      );

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      /*
       * Do not allow stale rewritten
       * HTML to be reused by a shared
       * intermediary.
       */
      res.setHeader(
        "Cache-Control",
        "private, no-store"
      );

      return res.send(
        html
      );
    }

    /* =====================================================
       EVERYTHING ELSE
    ===================================================== */

    res.status(
      response.status
    );

    copyResponseHeaders(
      response,
      res
    );

    return streamResponse(
      response,
      res
    );

  } catch (error) {
    console.error(
      "Proxy error:",
      error
    );

    /*
     * If the upstream navigation
     * failed before completion, don't
     * leave the cooldown stuck.
     */
    if (navigation) {
      session.lastNavigationAt =
        0;
    }

    return res
      .status(502)
      .send(
        "Proxy fetch failed: " +
        error.message
      );
  }
}

/* =========================================================
   /OPEN
========================================================= */

app.get(
  "/open",
  (req, res) => {
    const target =
      req.query.url;

    if (!target) {
      return res
        .status(400)
        .send(
          "Missing url"
        );
    }

    if (
      !isHttpUrl(target)
    ) {
      return res
        .status(400)
        .send(
          "Invalid HTTP(S) url"
        );
    }

    const sid =
      createSession(
        target,
        req.query.inject
      );

    setSessionCookie(
      res,
      sid
    );

    return res.redirect(
      proxyUrl(
        target,
        sid
      )
    );
  }
);

/* =========================================================
   SESSION STATUS
========================================================= */

app.get(
  "/session/status",
  (req, res) => {
    const found =
      getSession(req);

    if (!found) {
      return res
        .status(404)
        .json({
          error:
            "No proxy session"
        });
    }

    const session =
      found.session;

    resetBudgetIfNeeded(
      session
    );

    return res.json({
      sid:
        found.sid,

      target:
        session.target,

      dailyLimitSeconds:
        DAILY_LIMIT_MS / 1000,

      usedSeconds:
        Math.ceil(
          session.usedMs /
          1000
        ),

      remainingSeconds:
        Math.floor(
          remainingBudget(
            session
          ) / 1000
        ),

      cooldownMs:
        Math.max(
          0,
          NAVIGATION_COOLDOWN_MS -
          (
            Date.now() -
            session.lastNavigationAt
          )
        )
    });
  }
);

/* =========================================================
   SESSION PROXY
========================================================= */

app.all(
  "/proxy/:sid/:encoded",
  async (
    req,
    res
  ) => {
    const sid =
      req.params.sid;

    if (
      !sessions.has(sid)
    ) {
      return res
        .status(404)
        .send(
          "Proxy session expired"
        );
    }

    let url;

    try {
      url =
        decode(
          req.params.encoded
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid proxy URL"
        );
    }

    if (
      !isHttpUrl(url)
    ) {
      return res
        .status(400)
        .send(
          "Invalid proxy URL"
        );
    }

    return handleProxy(
      req,
      res,
      url,
      sid
    );
  }
);

/* =========================================================
   /PROXY?URL=
========================================================= */

app.all(
  "/proxy",
  async (
    req,
    res
  ) => {
    const url =
      req.query.url;

    if (!url) {
      return res
        .status(400)
        .send(
          "Missing url"
        );
    }

    if (
      !isHttpUrl(url)
    ) {
      return res
        .status(400)
        .send(
          "Invalid url"
        );
    }

    let found =
      getSession(
        req,
        req.query.sid ||
          null
      );

    if (!found) {
      const sid =
        createSession(
          url,
          req.query.inject
        );

      found = {
        sid,
        session:
          sessions.get(sid)
      };
    }

    setSessionCookie(
      res,
      found.sid
    );

    return handleProxy(
      req,
      res,
      url,
      found.sid
    );
  }
);

/* =========================================================
   /RESULTS
   RETAINED
========================================================= */

app.all(
  "/results",
  async (
    req,
    res
  ) => {
    let sid =
      req.query.sid;

    /*
     * First use explicit sid.
     */
    if (
      !sid ||
      !sessions.has(sid)
    ) {
      /*
       * Then use session cookie.
       */
      const cookieSid =
        getCookie(
          req,
          "orbit_sid"
        );

      if (
        cookieSid &&
        sessions.has(cookieSid)
      ) {
        sid =
          cookieSid;
      }
    }

    /*
     * Finally try Referer for old
     * Orbit behaviour.
     */
    if (
      !sid ||
      !sessions.has(sid)
    ) {
      const referer =
        req.headers.referer ||
        "";

      const match =
        referer.match(
          /\/proxy\/([^/]+)\//
        );

      if (match) {
        sid =
          decodeURIComponent(
            match[1]
          );
      }
    }

    if (
      !sid ||
      !sessions.has(sid)
    ) {
      return res
        .status(400)
        .send(
          "Missing proxy session"
        );
    }

    const session =
      sessions.get(sid);

    let base;

    try {
      base =
        new URL(
          session.target
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid target"
        );
    }

    /*
     * /results is kept for compatibility,
     * but the origin comes from the current
     * session. No website is hardcoded.
     */
    const queryIndex =
      req.originalUrl.indexOf(
        "?"
      );

    const query =
      queryIndex >= 0
        ? req.originalUrl.substring(
            queryIndex
          )
        : "";

    const target =
      new URL(
        "/results" +
        query,
        base.origin
      ).href;

    return handleProxy(
      req,
      res,
      target,
      sid
    );
  }
);

/* =========================================================
   /WATCH
   RETAINED AS DYNAMIC COMPATIBILITY
========================================================= */

app.all(
  "/watch",
  async (
    req,
    res
  ) => {
    let sid =
      req.query.sid;

    if (
      !sid ||
      !sessions.has(sid)
    ) {
      const cookieSid =
        getCookie(
          req,
          "orbit_sid"
        );

      if (
        cookieSid &&
        sessions.has(cookieSid)
      ) {
        sid =
          cookieSid;
      }
    }

    if (
      !sid ||
      !sessions.has(sid)
    ) {
      const referer =
        req.headers.referer ||
        "";

      const match =
        referer.match(
          /\/proxy\/([^/]+)\//
        );

      if (match) {
        sid =
          decodeURIComponent(
            match[1]
          );
      }
    }

    if (
      !sid ||
      !sessions.has(sid)
    ) {
      return res
        .status(400)
        .send(
          "Missing proxy session"
        );
    }

    const session =
      sessions.get(sid);

    let base;

    try {
      base =
        new URL(
          session.target
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid target"
        );
    }

    const queryIndex =
      req.originalUrl.indexOf(
        "?"
      );

    const query =
      queryIndex >= 0
        ? req.originalUrl.substring(
            queryIndex
          )
        : "";

    const target =
      new URL(
        "/watch" +
        query,
        base.origin
      ).href;

    return handleProxy(
      req,
      res,
      target,
      sid
    );
  }
);

/* =========================================================
   GENERIC DYNAMIC PATH
========================================================= */

app.all(
  "/__path",
  async (
    req,
    res
  ) => {
    const found =
      getSession(
        req,
        req.query.sid ||
          null
      );

    if (!found) {
      return res
        .status(404)
        .send(
          "Proxy session expired"
        );
    }

    let base;

    try {
      base =
        new URL(
          found.session.target
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid target session"
        );
    }

    const requestedPath =
      String(
        req.query.path ||
        "/"
      );

    if (
      !requestedPath.startsWith(
        "/"
      )
    ) {
      return res
        .status(400)
        .send(
          "Invalid path"
        );
    }

    const target =
      new URL(
        requestedPath,
        base.origin
      ).href;

    return handleProxy(
      req,
      res,
      target,
      found.sid
    );
  }
);

/* =========================================================
   DYNAMIC NAVIGATION
========================================================= */

app.all(
  "/__navigate",
  async (
    req,
    res
  ) => {
    const found =
      getSession(
        req,
        req.query.sid ||
          null
      );

    if (!found) {
      return res
        .status(404)
        .send(
          "Proxy session expired"
        );
    }

    const targetUrl =
      req.query.url;

    if (
      !targetUrl ||
      !isHttpUrl(targetUrl)
    ) {
      return res
        .status(400)
        .send(
          "Invalid navigation URL"
        );
    }

    /*
     * Navigation stays inside the
     * current website origin.
     */
    let sessionOrigin;

    try {
      sessionOrigin =
        new URL(
          found.session.target
        ).origin;
    } catch {
      return res
        .status(400)
        .send(
          "Invalid session target"
        );
    }

    let target;

    try {
      target =
        new URL(
          targetUrl
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid navigation URL"
        );
    }

    if (
      target.origin !==
      sessionOrigin
    ) {
      return res
        .status(403)
        .send(
          "Navigation target is outside the session"
        );
    }

    return handleProxy(
      req,
      res,
      target.href,
      found.sid
    );
  }
);

/* =========================================================
   EXTERNAL FETCH
========================================================= */

app.all(
  "/__external",
  async (
    req,
    res
  ) => {
    const sid =
      req.query.sid ||
      getCookie(
        req,
        "orbit_sid"
      );

    const url =
      req.query.url;

    /*
     * IMPORTANT:
     * This is session-bound.
     * It is not an anonymous open proxy.
     */
    if (
      !sid ||
      !sessions.has(sid)
    ) {
      return res
        .status(404)
        .send(
          "Missing proxy session"
        );
    }

    if (
      !url ||
      !isHttpUrl(url)
    ) {
      return res
        .status(400)
        .send(
          "Invalid external URL"
        );
    }

    return handleProxy(
      req,
      res,
      url,
      sid
    );
  }
);

/* =========================================================
   CUSTOM INJECTION
========================================================= */

app.post(
  "/inject",
  (req, res) => {
    const code =
      req.body
        ? req.body.toString(
            "utf8"
          )
        : "";

    if (!code.trim()) {
      return res
        .status(400)
        .json({
          error:
            "No code supplied"
        });
    }

    if (
      Buffer.byteLength(
        code,
        "utf8"
      ) >
      MAX_INJECTION_BYTES
    ) {
      return res
        .status(413)
        .json({
          error:
            "Injection code too large"
        });
    }

    const id =
      makeId();

    injections.set(
      id,
      {
        code,
        created:
          Date.now()
      }
    );

    return res.json({
      id,

      script:
        `/inject/${id}.js`
    });
  }
);

app.get(
  "/inject/:id.js",
  (req, res) => {
    const item =
      injections.get(
        req.params.id
      );

    if (!item) {
      return res
        .status(404)
        .type(
          "text/plain"
        )
        .send(
          "// Not found"
        );
    }

    res.setHeader(
      "Content-Type",
      "application/javascript; charset=utf-8"
    );

    res.setHeader(
      "Cache-Control",
      "no-store"
    );

    return res.send(
      item.code
    );
  }
);

/* =========================================================
   RAW SOURCE
========================================================= */

app.get(
  "/source",
  async (
    req,
    res
  ) => {
    const target =
      req.query.url;

    if (
      !target ||
      !isHttpUrl(target)
    ) {
      return res
        .status(400)
        .send(
          "Invalid url"
        );
    }

    const sid =
      createSession(
        target
      );

    const session =
      sessions.get(sid);

    try {
      const response =
        await fetchTarget(
          target,
          req,
          sid
        );

      saveCookies(
        response,
        session,
        target
      );

      const data =
        Buffer.from(
          await response.arrayBuffer()
        );

      /*
       * /source means RAW source.
       * No rewrite.
       * No extension.
       * No bridge.
       */
      res.status(
        response.status
      );

      res.setHeader(
        "Content-Type",
        "text/plain; charset=utf-8"
      );

      res.setHeader(
        "Cache-Control",
        "private, no-store"
      );

      return res.send(
        data
      );
    } catch (error) {
      return res
        .status(502)
        .send(
          "Source fetch failed: " +
          error.message
        );
    }
  }
);

/* =========================================================
   CACHE / SOURCE INFO
========================================================= */

app.get(
  "/cache/info",
  (req, res) => {
    const found =
      getSession(req);

    if (!found) {
      return res
        .status(404)
        .json({
          error:
            "No proxy session"
        });
    }

    return res.json({
      sid:
        found.sid,

      browserCache:
        true,

      cacheName:
        "orbit-cache-" +
        found.sid,

      note:
        "Resources are cached by Orbit in the browser. Missing resources fall back to the proxy."
    });
  }
);

/* =========================================================
   HOME
========================================================= */

app.get(
  "/",
  (req, res) => {
    return res.json({
      name:
        "Orbit Source Proxy",

      status:
        "online",

      architecture:
        "dynamic-session-proxy",

      dailyLimitSeconds:
        DAILY_LIMIT_MS / 1000,

      navigationCooldownSeconds:
        NAVIGATION_COOLDOWN_MS / 1000,

      features: [
        "dynamic URL proxy",
        "isolated sessions",
        "isolated target cookies",
        "HTML rewriting",
        "fetch bridge",
        "XHR bridge",
        "browser resource cache",
        "browser extension storage",
        "dynamic redirects",
        "streaming resources",
        "raw source",
        "results compatibility",
        "watch compatibility",
        "daily request budget"
      ],

      routes: {
        open:
          "/open?url=https://example.com",

        proxy:
          "/proxy?url=https://example.com",

        results:
          "/results",

        watch:
          "/watch",

        source:
          "/source?url=https://example.com",

        inject:
          "POST /inject",

        status:
          "/session/status",

        cache:
          "/cache/info"
      }
    });
  }
);

/* =========================================================
   CLEANUP
========================================================= */

setInterval(
  () => {
    const now =
      Date.now();

    /*
     * Remove expired sessions.
     */
    for (
      const [
        sid,
        session
      ] of sessions
    ) {
      if (
        now -
          session.created >
        SESSION_TTL_MS
      ) {
        sessions.delete(
          sid
        );
      }
    }

    /*
     * Remove expired injections.
     */
    for (
      const [
        id,
        item
      ] of injections
    ) {
      if (
        now -
          item.created >
        INJECTION_TTL_MS
      ) {
        injections.delete(
          id
        );
      }
    }
  },
  30 * 60 * 1000
);

/* =========================================================
   SERVER
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Orbit Source Proxy running on port ${PORT}`
    );
  }
);
