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

/* =========================================================
   LIMITS
========================================================= */

const DAILY_LIMIT_MS = 10 * 60 * 1000;

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
  return Buffer.from(
    String(value),
    "utf8"
  ).toString("base64url");
}

function decode(value) {
  return Buffer.from(
    String(value),
    "base64url"
  ).toString("utf8");
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
    return new URL(
      value,
      base
    ).href;
  } catch {
    return null;
  }
}

function proxyUrl(url, sid) {
  return (
    "/proxy/" +
    encodeURIComponent(sid) +
    "/" +
    encode(url)
  );
}

function shouldSkipUrl(value) {
  const v =
    String(value || "")
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
  const header =
    req.headers.cookie || "";

  const escaped =
    name.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    );

  const match =
    header.match(
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

function createSession(
  target,
  injection = null
) {
  const sid = makeId();

  sessions.set(
    sid,
    {
      target,

      created:
        Date.now(),

      lastActivity:
        Date.now(),

      /*
       * Real cookie jar for the complete
       * proxied session.
       *
       * Cookies are matched by:
       *   domain
       *   path
       *   secure
       *
       * instead of only target origin.
       *
       * This is important for authentication
       * systems that move between subdomains.
       */
      cookies:
        new Map(),

      injection:
        typeof injection ===
          "string" &&
        injection.trim()
          ? injection
          : null,

      budgetDay:
        Date.now(),

      usedMs:
        0
    }
  );

  return sid;
}

function getSession(
  req,
  sid = null
) {
  if (
    sid &&
    sessions.has(sid)
  ) {
    return {
      sid,
      session:
        sessions.get(sid)
    };
  }

  const cookieSid =
    getCookie(
      req,
      "orbit_sid"
    );

  if (
    cookieSid &&
    sessions.has(cookieSid)
  ) {
    return {
      sid:
        cookieSid,

      session:
        sessions.get(
          cookieSid
        )
    };
  }

  return null;
}

/* =========================================================
   DAILY TIME LIMIT
========================================================= */

function resetBudgetIfNeeded(
  session
) {
  const now =
    Date.now();

  if (
    !session.budgetDay ||
    now -
      session.budgetDay >=
      24 * 60 * 60 * 1000
  ) {
    session.budgetDay =
      now;

    session.usedMs =
      0;
  }
}

function remainingBudget(
  session
) {
  resetBudgetIfNeeded(
    session
  );

  return Math.max(
    0,
    DAILY_LIMIT_MS -
      session.usedMs
  );
}

function isNavigationRequest(
  req
) {
  if (
    req.method !== "GET" &&
    req.method !== "HEAD"
  ) {
    return false;
  }

  const accept =
    String(
      req.headers.accept ||
        ""
    ).toLowerCase();

  const secFetchDest =
    String(
      req.headers[
        "sec-fetch-dest"
      ] || ""
    ).toLowerCase();

  return (
    secFetchDest ===
      "document" ||
    accept.includes(
      "text/html"
    ) ||
    req.path === "/open"
  );
}

function navigationAllowed(
  session
) {
  resetBudgetIfNeeded(
    session
  );

  if (
    remainingBudget(
      session
    ) <= 0
  ) {
    return {
      ok: false,
      reason:
        "daily-limit"
    };
  }

  return {
    ok: true
  };
}

function chargeNavigation(
  session,
  elapsed
) {
  resetBudgetIfNeeded(
    session
  );

  session.usedMs +=
    Math.max(
      0,
      elapsed
    );
}

/* =========================================================
   COOKIE JAR
========================================================= */

function defaultCookiePath(
  targetUrl
) {
  try {
    const pathname =
      new URL(
        targetUrl
      ).pathname || "/";

    if (
      !pathname.startsWith(
        "/"
      )
    ) {
      return "/";
    }

    if (
      pathname === "/"
    ) {
      return "/";
    }

    const index =
      pathname.lastIndexOf(
        "/"
      );

    if (
      index <= 0
    ) {
      return "/";
    }

    return (
      pathname.slice(
        0,
        index
      ) || "/"
    );
  } catch {
    return "/";
  }
}

function parseSetCookie(
  raw,
  targetUrl
) {
  const pieces =
    String(raw)
      .split(";")
      .map(
        part =>
          part.trim()
      );

  if (
    !pieces[0]
  ) {
    return null;
  }

  const eq =
    pieces[0].indexOf(
      "="
    );

  if (
    eq <= 0
  ) {
    return null;
  }

  const name =
    pieces[0]
      .slice(0, eq)
      .trim();

  const value =
    pieces[0]
      .slice(eq + 1)
      .trim();

  let url;

  try {
    url =
      new URL(
        targetUrl
      );
  } catch {
    return null;
  }

  let domain =
    url.hostname.toLowerCase();

  let hostOnly =
    true;

  let path =
    defaultCookiePath(
      targetUrl
    );

  let expiresAt =
    null;

  let secure =
    false;

  for (
    let i = 1;
    i < pieces.length;
    i++
  ) {
    const part =
      pieces[i];

    const separator =
      part.indexOf(
        "="
      );

    const attrName =
      (
        separator >= 0
          ? part.slice(
              0,
              separator
            )
          : part
      )
        .trim()
        .toLowerCase();

    const attrValue =
      separator >= 0
        ? part
            .slice(
              separator + 1
            )
            .trim()
        : "";

    if (
      attrName ===
        "domain" &&
      attrValue
    ) {
      const clean =
        attrValue
          .replace(
            /^\./,
            ""
          )
          .toLowerCase();

      if (clean) {
        domain =
          clean;

        hostOnly =
          false;
      }
    } else if (
      attrName ===
        "path" &&
      attrValue.startsWith(
        "/"
      )
    ) {
      path =
        attrValue;
    } else if (
      attrName ===
        "max-age"
    ) {
      const seconds =
        Number(
          attrValue
        );

      if (
        Number.isFinite(
          seconds
        )
      ) {
        expiresAt =
          Date.now() +
          Math.max(
            0,
            seconds
          ) *
            1000;
      }
    } else if (
      attrName ===
        "expires" &&
      attrValue
    ) {
      const time =
        Date.parse(
          attrValue
        );

      if (
        Number.isFinite(
          time
        )
      ) {
        expiresAt =
          time;
      }
    } else if (
      attrName ===
        "secure"
    ) {
      secure =
        true;
    }
  }

  return {
    name,
    value,
    domain,
    hostOnly,
    path:
      path || "/",
    expiresAt,
    secure,
    createdAt:
      Date.now()
  };
}

function cookieDomainMatches(
  cookie,
  hostname
) {
  const host =
    String(
      hostname || ""
    ).toLowerCase();

  const domain =
    String(
      cookie.domain || ""
    ).toLowerCase();

  if (
    !host ||
    !domain
  ) {
    return false;
  }

  if (
    cookie.hostOnly
  ) {
    return (
      host === domain
    );
  }

  return (
    host === domain ||
    host.endsWith(
      "." + domain
    )
  );
}

function cookiePathMatches(
  cookiePathValue,
  requestPath
) {
  const pathValue =
    cookiePathValue ||
    "/";

  const path =
    requestPath || "/";

  if (
    pathValue === "/"
  ) {
    return true;
  }

  if (
    path === pathValue
  ) {
    return true;
  }

  if (
    !path.startsWith(
      pathValue
    )
  ) {
    return false;
  }

  return (
    pathValue.endsWith(
      "/"
    ) ||
    path[
      pathValue.length
    ] === "/"
  );
}

function cookieKey(
  cookie
) {
  return [
    cookie.name,
    cookie.domain,
    cookie.path
  ].join("\u0000");
}

function cookieHeader(
  session,
  targetUrl
) {
  if (
    !session ||
    !session.cookies
  ) {
    return "";
  }

  let url;

  try {
    url =
      new URL(
        targetUrl
      );
  } catch {
    return "";
  }

  const now =
    Date.now();

  const matched =
    [];

  for (
    const [
      key,
      cookie
    ] of session.cookies
  ) {
    if (!cookie) {
      session.cookies.delete(
        key
      );

      continue;
    }

    if (
      cookie.expiresAt !==
        null &&
      cookie.expiresAt <=
        now
    ) {
      session.cookies.delete(
        key
      );

      continue;
    }

    if (
      cookie.secure &&
      url.protocol !==
        "https:"
    ) {
      continue;
    }

    if (
      !cookieDomainMatches(
        cookie,
        url.hostname
      )
    ) {
      continue;
    }

    if (
      !cookiePathMatches(
        cookie.path,
        url.pathname
      )
    ) {
      continue;
    }

    matched.push(
      cookie
    );
  }

  matched.sort(
    (a, b) =>
      b.path.length -
      a.path.length
  );

  return matched
    .map(
      cookie =>
        `${cookie.name}=${cookie.value}`
    )
    .join("; ");
}

function saveCookies(
  response,
  session,
  targetUrl
) {
  if (!session) {
    return;
  }

  let setCookies =
    [];

  if (
    typeof response
      .headers
      .getSetCookie ===
    "function"
  ) {
    setCookies =
      response
        .headers
        .getSetCookie();
  } else {
    const single =
      response.headers.get(
        "set-cookie"
      );

    if (single) {
      setCookies =
        [single];
    }
  }

  if (
    !setCookies.length
  ) {
    return;
  }

  for (
    const raw of setCookies
  ) {
    const cookie =
      parseSetCookie(
        raw,
        targetUrl
      );

    if (!cookie) {
      continue;
    }

    const key =
      cookieKey(
        cookie
      );

    if (
      cookie.expiresAt !==
        null &&
      cookie.expiresAt <=
        Date.now()
    ) {
      session.cookies.delete(
        key
      );

      continue;
    }

    session.cookies.set(
      key,
      cookie
    );
  }
}

/* =========================================================
   REQUEST HEADERS
========================================================= */

function buildTargetHeaders(
  req,
  targetUrl
) {
  let target;

  try {
    target =
      new URL(
        targetUrl
      );
  } catch {
    target =
      null;
  }

  const headers = {
    "user-agent":
      req.headers[
        "user-agent"
      ] ||
      "Mozilla/5.0",

    "accept":
      req.headers.accept ||
      "*/*",

    "accept-language":
      req.headers[
        "accept-language"
      ] ||
      "en-US,en;q=0.9"
  };

  /*
   * Forward the browser's real
   * device/client-hint information.
   *
   * Nothing here invents a
   * desktop/mobile resolution.
   */
  const passthrough = [
    "content-type",
    "content-length",
    "range",

    "if-none-match",
    "if-modified-since",

    "cache-control",
    "pragma",

    "accept-encoding",

    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",

    "sec-ch-viewport-width",
    "sec-ch-viewport-height",

    "dpr",
    "viewport-width",
    "device-memory",

    "save-data",
    "downlink",
    "ect",
    "rtt",

    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-user"
  ];

  for (
    const name of
      passthrough
  ) {
    if (
      req.headers[name] !==
      undefined
    ) {
      headers[name] =
        req.headers[name];
    }
  }

  /*
   * The browser's Origin normally
   * contains the Render origin.
   *
   * For upstream authentication/CORS
   * systems, use the current target
   * origin instead of leaking the
   * proxy origin.
   */
  if (
    req.headers.origin &&
    target
  ) {
    headers.origin =
      target.origin;
  }

  /*
   * Translate a proxied Referer
   * back to the upstream URL.
   */
  if (
    req.headers.referer
  ) {
    const rawReferer =
      String(
        req.headers.referer
      );

    let upstreamReferer =
      null;

    const marker =
      "/proxy/";

    const markerIndex =
      rawReferer.indexOf(
        marker
      );

    if (
      markerIndex >= 0
    ) {
      const rest =
        rawReferer.slice(
          markerIndex +
            marker.length
        );

      const slash =
        rest.indexOf(
          "/"
        );

      if (
        slash > 0
      ) {
        const encoded =
          rest
            .slice(
              slash + 1
            )
            .split(
              /[?#]/
            )[0];

        try {
          const decoded =
            decode(
              encoded
            );

          if (
            isHttpUrl(
              decoded
            )
          ) {
            upstreamReferer =
              decoded;
          }
        } catch {}
      }
    }

    headers.referer =
      upstreamReferer ||
      (
        target
          ? target.href
          : rawReferer
      );
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
    sessions.get(
      sid
    );

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
    method:
      req.method,

    headers,

    redirect:
      "manual"
  };

  if (
    req.method !==
      "GET" &&
    req.method !==
      "HEAD" &&
    req.body &&
    req.body.length
  ) {
    options.body =
      req.body;
  }

  return fetch(
    url,
    options
  );
}

/* =========================================================
   RESPONSE HEADERS
========================================================= */

const HOP_BY_HOP_HEADERS =
  new Set([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",

    /*
     * Prevent upstream origin
     * security context from blocking
     * the Render iframe.
     */
    "x-frame-options",

    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "origin-agent-cluster",

    /*
     * CSP is handled separately.
     */

    "content-length",
    "content-encoding",

    /*
     * Upstream cookies are stored
     * in the private session jar.
     */
    "set-cookie"
  ]);

function sanitizeContentSecurityPolicy(
  value
) {
  if (!value) {
    return value;
  }

  return String(
    value
  )
    .split(";")
    .map(
      part =>
        part.trim()
    )
    .filter(
      part => {
        if (!part) {
          return false;
        }

        return !/^frame-ancestors(?:\s|$)/i.test(
          part
        );
      }
    )
    .join("; ");
}

function stripHTMLSecurityPolicies(
  html
) {
  return String(
    html
  ).replace(
    /<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy(?:-report-only)?["']?[^>]*>/gi,
    ""
  );
}

function copyResponseHeaders(
  response,
  res
) {
  for (
    const [
      name,
      value
    ] of response.headers
  ) {
    const lower =
      name.toLowerCase();

    if (
      HOP_BY_HOP_HEADERS.has(
        lower
      )
    ) {
      continue;
    }

    if (
      lower ===
      "content-security-policy"
    ) {
      const cleaned =
        sanitizeContentSecurityPolicy(
          value
        );

      if (cleaned) {
        res.setHeader(
          name,
          cleaned
        );
      }

      continue;
    }

    if (
      lower ===
      "content-security-policy-report-only"
    ) {
      const cleaned =
        sanitizeContentSecurityPolicy(
          value
        );

      if (cleaned) {
        res.setHeader(
          name,
          cleaned
        );
      }

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
    typeof response.body
      .getReader ===
      "function"
  ) {
    const reader =
      response.body
        .getReader();

    try {
      while (true) {
        const {
          done,
          value
        } =
          await reader.read();

        if (done) {
          break;
        }

        if (
          !res.write(
            Buffer.from(
              value
            )
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
        res.destroy(
          error
        );
      } catch {}

      return;
    }
  }

  const buffer =
    Buffer.from(
      await response.arrayBuffer()
    );

  res.send(
    buffer
  );
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
   * Force every normal HTML
   * navigation into same tab.
   */

  html =
    html.replace(
      /\s+target\s*=\s*(["'])[^"']*\1/gi,
      ' target="_self"'
    );

  html =
    html.replace(
      /\s+target\s*=\s*[^\s>]+/gi,
      ' target="_self"'
    );

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

  for (
    const attr of attrs
  ) {
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
            shouldSkipUrl(
              value
            )
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
            !isHttpUrl(
              url
            )
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
            .map(
              part => {
                const pieces =
                  part
                    .trim()
                    .split(
                      /\s+/
                    );

                if (
                  !pieces[0]
                ) {
                  return part;
                }

                const url =
                  absolute(
                    pieces[0],
                    target
                  );

                if (
                  url &&
                  isHttpUrl(
                    url
                  )
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
              }
            )
            .join(
              ", "
            );

        return (
          start +
          result +
          end
        );
      }
    );

  /* =====================================================
     CSS URL
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
          shouldSkipUrl(
            value
          )
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
          !isHttpUrl(
            url
          )
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
     BASE TAG
  ===================================================== */

  html =
    html.replace(
      /<base\b([^>]*?)\bhref\s*=\s*(["'])(.*?)\2([^>]*)>/gi,
      (
        full,
        before,
        quote,
        value,
        after
      ) => {
        const url =
          absolute(
            value.trim(),
            target
          );

        if (
          !url ||
          !isHttpUrl(
            url
          )
        ) {
          return full;
        }

        return (
          "<base" +
          before +
          'href="' +
          proxyUrl(
            url,
            sid
          ) +
          '"' +
          after +
          ">"
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
          !isHttpUrl(
            url
          )
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
    sessions.get(
      sid
    );

  const injectionId =
    session?.injection ||
    null;

  const bridge = `
<script>
(() => {
  "use strict";

  const ORBIT_SID =
    ${JSON.stringify(
      sid
    )};

  const ORBIT_TARGET =
    ${JSON.stringify(
      target
    )};

  const CACHE_NAME =
    "orbit-cache-" +
    ORBIT_SID;

  const EXTENSION_KEY =
    "orbit-extension-" +
    ORBIT_SID;

  const nativeFetch =
    window.fetch.bind(
      window
    );

  const NativeXHR =
    window.XMLHttpRequest;

  function resolveTargetUrl(
    value
  ) {
    try {
      return new URL(
        typeof value ===
          "string"
          ? value
          : value.url,
        ORBIT_TARGET
      ).href;
    } catch {
      return null;
    }
  }

  function proxyUrlForTarget(
    url
  ) {
    const bytes =
      new TextEncoder()
        .encode(url);

    let binary = "";

    for (
      let i = 0;
      i < bytes.length;
      i++
    ) {
      binary +=
        String.fromCharCode(
          bytes[i]
        );
    }

    const encoded =
      btoa(binary)
        .replace(
          /=+$/g,
          ""
        )
        .replace(
          /\\+/g,
          "-"
        )
        .replace(
          /\\//g,
          "_"
        );

    return (
      "/proxy/" +
      encodeURIComponent(
        ORBIT_SID
      ) +
      "/" +
      encoded
    );
  }

  function isOrbitUrl(
    url
  ) {
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

      let response =
        await cache.match(
          targetUrl
        );

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
      return this.read(
        url
      );
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
        await this.read(
          url
        );

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
      xhr.open.bind(
        xhr
      );

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
     STRICT SAME-RENDER NAVIGATION
  ===================================================== */

  function orbitProxyTarget(
    value
  ) {
    const targetUrl =
      resolveTargetUrl(
        value
      );

    if (!targetUrl) {
      return null;
    }

    return proxyUrlForTarget(
      targetUrl
    );
  }

  function orbitNavigate(
    value
  ) {
    const proxy =
      orbitProxyTarget(
        value
      );

    if (!proxy) {
      return false;
    }

    window.location.assign(
      proxy
    );

    return true;
  }

  window.open =
    function(value) {
      if (
        orbitNavigate(
          value
        )
      ) {
        return window;
      }

      return window;
    };

  /* =====================================================
     ANCHORS
  ===================================================== */

  function rewriteAnchor(
    anchor
  ) {
    if (!anchor) {
      return;
    }

    anchor.setAttribute(
      "target",
      "_self"
    );

    const raw =
      anchor.getAttribute(
        "href"
      );

    if (!raw) {
      return;
    }

    const trimmed =
      raw.trim();

    if (
      trimmed.startsWith(
        "#"
      ) ||
      trimmed.startsWith(
        "javascript:"
      ) ||
      trimmed.startsWith(
        "mailto:"
      ) ||
      trimmed.startsWith(
        "tel:"
      ) ||
      trimmed.startsWith(
        "data:"
      ) ||
      trimmed.startsWith(
        "blob:"
      )
    ) {
      return;
    }

    const proxy =
      orbitProxyTarget(
        trimmed
      );

    if (proxy) {
      anchor.setAttribute(
        "href",
        proxy
      );
    }
  }

  function rewriteForm(
    form
  ) {
    if (!form) {
      return;
    }

    form.setAttribute(
      "target",
      "_self"
    );

    const raw =
      form.getAttribute(
        "action"
      ) ||
      window.location.href;

    const proxy =
      orbitProxyTarget(
        raw
      );

    if (proxy) {
      form.setAttribute(
        "action",
        proxy
      );
    }
  }

  function rewriteNavigationTree(
    root
  ) {
    if (
      !root ||
      !root.querySelectorAll
    ) {
      return;
    }

    if (
      root.matches &&
      root.matches("a")
    ) {
      rewriteAnchor(
        root
      );
    }

    if (
      root.matches &&
      root.matches("form")
    ) {
      rewriteForm(
        root
      );
    }

    root
      .querySelectorAll(
        "a"
      )
      .forEach(
        rewriteAnchor
      );

    root
      .querySelectorAll(
        "form"
      )
      .forEach(
        rewriteForm
      );
  }

  document.addEventListener(
    "click",
    function(event) {
      const anchor =
        event.target &&
        event.target.closest
          ? event.target.closest(
              "a"
            )
          : null;

      if (!anchor) {
        return;
      }

      rewriteAnchor(
        anchor
      );

      const href =
        anchor.getAttribute(
          "href"
        );

      const proxy =
        orbitProxyTarget(
          href
        );

      if (proxy) {
        event.preventDefault();

        event.stopImmediatePropagation();

        window.location.assign(
          proxy
        );
      }
    },
    true
  );

  document.addEventListener(
    "auxclick",
    function(event) {
      const anchor =
        event.target &&
        event.target.closest
          ? event.target.closest(
              "a"
            )
          : null;

      if (!anchor) {
        return;
      }

      const href =
        anchor.getAttribute(
          "href"
        );

      const proxy =
        orbitProxyTarget(
          href
        );

      if (proxy) {
        event.preventDefault();

        event.stopImmediatePropagation();

        window.location.assign(
          proxy
        );
      }
    },
    true
  );

  document.addEventListener(
    "submit",
    function(event) {
      const form =
        event.target;

      if (!form) {
        return;
      }

      rewriteForm(
        form
      );
    },
    true
  );

  if (
    typeof MutationObserver !==
    "undefined"
  ) {
    const observer =
      new MutationObserver(
        mutations => {
          for (
            const mutation of
              mutations
          ) {
            for (
              const node of
                mutation.addedNodes
            ) {
              if (
                node.nodeType ===
                1
              ) {
                rewriteNavigationTree(
                  node
                );
              }
            }
          }
        }
      );

    if (
      document.documentElement
    ) {
      observer.observe(
        document.documentElement,
        {
          childList: true,
          subtree: true
        }
      );
    }
  }

  rewriteNavigationTree(
    document
  );

  window.OrbitSource.navigate =
    orbitNavigate;

  window.OrbitSource.proxy =
    orbitProxyTarget;

  window.OrbitExtension.open =
    orbitNavigate;

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
      {
        once: true
      }
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
    /<head[^>]*>/i.test(
      html
    )
  ) {
    html =
      html.replace(
        /<head[^>]*>/i,
        match =>
          match +
          bridge
      );
  } else {
    html =
      bridge +
      html;
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
      /<head[^>]*>/i.test(
        html
      )
    ) {
      html =
        html.replace(
          /<head[^>]*>/i,
          match =>
            match +
            script
        );
    } else {
      html =
        script +
        html;
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
    sessions.get(
      sid
    );

  if (!session) {
    return res
      .status(404)
      .send(
        "Proxy session expired"
      );
  }

  session.lastActivity =
    Date.now();

  if (
    !isHttpUrl(url)
  ) {
    return res
      .status(400)
      .send(
        "Only HTTP(S) URLs are supported"
      );
  }

  const navigation =
    isNavigationRequest(
      req
    );

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
              DAILY_LIMIT_MS /
              1000,

            usedSeconds:
              Math.ceil(
                session.usedMs /
                  1000
              ),

            remainingSeconds:
              Math.floor(
                remainingBudget(
                  session
                ) /
                  1000
              )
          });
      }
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

    if (navigation) {
      chargeNavigation(
        session,
        Date.now() -
          started
      );
    }

    setSessionCookie(
      res,
      sid
    );

    /*
     * Ask the browser for real
     * client/device hints.
     *
     * No fixed resolution.
     */
    res.setHeader(
      "Accept-CH",
      "Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-Viewport-Width, Sec-CH-Viewport-Height, DPR, Device-Memory, Save-Data, Downlink, ECT, RTT"
    );

    /* =====================================================
       REDIRECT
    ===================================================== */

    if (
      response.status >=
        300 &&
      response.status <
        400
    ) {
      const location =
        response.headers.get(
          "location"
        );

      /*
       * Never expose upstream
       * redirect destinations.
       */
      if (location) {
        const next =
          absolute(
            location,
            url
          );

        if (
          next &&
          isHttpUrl(
            next
          )
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

      res.setHeader(
        "Cache-Control",
        "no-store"
      );

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
        stripHTMLSecurityPolicies(
          rewriteHTML(
            data.toString(
              "utf8"
            ),
            url,
            sid
          )
        );

      res.status(
        response.status
      );

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      /*
       * Make upstream HTML
       * iframe-compatible.
       */
      res.removeHeader(
        "X-Frame-Options"
      );

      res.removeHeader(
        "Content-Security-Policy"
      );

      res.removeHeader(
        "Content-Security-Policy-Report-Only"
      );

      res.removeHeader(
        "Cross-Origin-Resource-Policy"
      );

      res.removeHeader(
        "Cross-Origin-Embedder-Policy"
      );

      res.removeHeader(
        "Cross-Origin-Opener-Policy"
      );

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
      !isHttpUrl(
        target
      )
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
        DAILY_LIMIT_MS /
        1000,

      usedSeconds:
        Math.ceil(
          session.usedMs /
            1000
        ),

      remainingSeconds:
        Math.floor(
          remainingBudget(
            session
          ) /
            1000
        ),

      navigationCooldown:
        false
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
      !sessions.has(
        sid
      )
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
      !isHttpUrl(
        url
      )
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
          sessions.get(
            sid
          )
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

    if (
      !sid ||
      !sessions.has(
        sid
      )
    ) {
      const cookieSid =
        getCookie(
          req,
          "orbit_sid"
        );

      if (
        cookieSid &&
        sessions.has(
          cookieSid
        )
      ) {
        sid =
          cookieSid;
      }
    }

    if (
      !sid ||
      !sessions.has(
        sid
      )
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
      !sessions.has(
        sid
      )
    ) {
      return res
        .status(400)
        .send(
          "Missing proxy session"
        );
    }

    const session =
      sessions.get(
        sid
      );

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
      !sessions.has(
        sid
      )
    ) {
      const cookieSid =
        getCookie(
          req,
          "orbit_sid"
        );

      if (
        cookieSid &&
        sessions.has(
          cookieSid
        )
      ) {
        sid =
          cookieSid;
      }
    }

    if (
      !sid ||
      !sessions.has(
        sid
      )
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
      !sessions.has(
        sid
      )
    ) {
      return res
        .status(400)
        .send(
          "Missing proxy session"
        );
    }

    const session =
      sessions.get(
        sid
      );

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
      !isHttpUrl(
        targetUrl
      )
    ) {
      return res
        .status(400)
        .send(
          "Invalid navigation URL"
        );
    }

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

    if (
      !sid ||
      !sessions.has(
        sid
      )
    ) {
      return res
        .status(404)
        .send(
          "Missing proxy session"
        );
    }

    if (
      !url ||
      !isHttpUrl(
        url
      )
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

    if (
      !code.trim()
    ) {
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
      !isHttpUrl(
        target
      )
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
      sessions.get(
        sid
      );

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
        "Resources are cached by Orbit in the browser. Authentication cookies remain private inside the proxy session."
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
        DAILY_LIMIT_MS /
        1000,

      navigationCooldown:
        false,

      features: [
        "dynamic URL proxy",
        "isolated sessions",
        "domain/path cookie jar",
        "authentication cookie persistence",
        "HTML rewriting",
        "same-tab navigation",
        "popup blocking",
        "target blank blocking",
        "fetch bridge",
        "XHR bridge",
        "browser resource cache",
        "browser extension storage",
        "dynamic redirects",
        "streaming resources",
        "client hints",
        "mobile and desktop UA forwarding",
        "responsive viewport hints",
        "iframe compatibility",
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

    for (
      const [
        sid,
        session
      ] of sessions
    ) {
      if (
        now -
          (
            session.lastActivity ||
            session.created
          ) >
        SESSION_TTL_MS
      ) {
        sessions.delete(
          sid
        );
      }
    }

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
