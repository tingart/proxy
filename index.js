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
 * }
 */

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
    usedMs: 0
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
    now - session.budgetDay >=
      24 * 60 * 60 * 1000
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

  if (
    remainingBudget(session) <= 0
  ) {
    return {
      ok: false,
      reason: "daily-limit"
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
 * Target cookies stay isolated by origin.
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

    const lower =
      String(raw).toLowerCase();

    if (
      lower.includes("max-age=0") ||
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
  "content-length",
  "content-encoding",
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

        if (value) {
          res.write(
            Buffer.from(value)
          );
        }
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {}
    }

    return res.end();
  }

  const buffer =
    Buffer.from(
      await response.arrayBuffer()
    );

  return res.end(buffer);
}

/* =========================================================
   BROWSER BRIDGE
========================================================= */

function buildBridge(
  sid,
  targetUrl
) {
  const sidJson =
    JSON.stringify(String(sid));

  const targetJson =
    JSON.stringify(String(targetUrl));

  return `
<script>
(function () {
  "use strict";

  if (window.__ORBIT_BRIDGE_LOADED__) {
    return;
  }

  window.__ORBIT_BRIDGE_LOADED__ = true;

  const ORBIT_SID = ${sidJson};
  const ORBIT_TARGET = ${targetJson};

  /* =======================================================
     URL HELPERS
  ======================================================= */

  function resolveTargetUrl(value) {
    try {
      return new URL(
        String(value),
        window.location.href
      ).href;
    } catch {
      return null;
    }
  }

  function isHttpUrl(value) {
    try {
      const u = new URL(value);

      return (
        u.protocol === "http:" ||
        u.protocol === "https:"
      );
    } catch {
      return false;
    }
  }

  function base64UrlEncode(value) {
    try {
      const bytes =
        new TextEncoder().encode(
          String(value)
        );

      let binary = "";

      const chunk = 0x8000;

      for (
        let i = 0;
        i < bytes.length;
        i += chunk
      ) {
        binary += String.fromCharCode(
          ...bytes.subarray(
            i,
            i + chunk
          )
        );
      }

      return btoa(binary)
        .replace(/=/g, "")
        .replace(/\\+/g, "-")
        .replace(/\\//g, "_");
    } catch {
      return "";
    }
  }

  function proxyUrlForTarget(value) {
    const resolved =
      resolveTargetUrl(value);

    if (!resolved) {
      return null;
    }

    if (!isHttpUrl(resolved)) {
      return null;
    }

    return (
      "/proxy/" +
      encodeURIComponent(ORBIT_SID) +
      "/" +
      base64UrlEncode(resolved)
    );
  }

  function navigateInsideOrbit(value) {
    const proxy =
      proxyUrlForTarget(value);

    if (!proxy) {
      return false;
    }

    window.location.assign(proxy);

    return true;
  }

  function isProxyUrl(value) {
    try {
      const u =
        new URL(
          String(value),
          window.location.href
        );

      return (
        u.origin ===
          window.location.origin &&
        u.pathname.startsWith(
          "/proxy/"
        )
      );
    } catch {
      return false;
    }
  }

  /* =======================================================
     CACHE STORAGE
  ======================================================= */

  const CACHE_NAME =
    "orbit-cache-" +
    ORBIT_SID;

  async function orbitCachePut(
    request,
    response
  ) {
    try {
      const cache =
        await caches.open(
          CACHE_NAME
        );

      await cache.put(
        request,
        response.clone()
      );

      return true;
    } catch {
      return false;
    }
  }

  async function orbitCacheMatch(
    request
  ) {
    try {
      const cache =
        await caches.open(
          CACHE_NAME
        );

      return await cache.match(
        request
      );
    } catch {
      return undefined;
    }
  }

  /* =======================================================
     ORBIT SOURCE API
  ======================================================= */

  window.OrbitSource = {
    sid: ORBIT_SID,

    target: ORBIT_TARGET,

    proxyUrl:
      function (url) {
        return proxyUrlForTarget(
          url
        );
      },

    navigate:
      function (url) {
        return navigateInsideOrbit(
          url
        );
      },

    cachePut:
      orbitCachePut,

    cacheMatch:
      orbitCacheMatch,

    cacheName:
      CACHE_NAME
  };

  /* =======================================================
     ORBIT EXTENSION API
  ======================================================= */

  const extensionStore =
    "orbit-extension-" +
    ORBIT_SID;

  window.OrbitExtension = {
    storage: {
      async get(key) {
        try {
          const raw =
            localStorage.getItem(
              extensionStore +
              ":" +
              key
            );

          return raw === null
            ? null
            : JSON.parse(raw);
        } catch {
          return null;
        }
      },

      async set(
        key,
        value
      ) {
        try {
          localStorage.setItem(
            extensionStore +
            ":" +
            key,
            JSON.stringify(value)
          );

          return true;
        } catch {
          return false;
        }
      },

      async remove(key) {
        try {
          localStorage.removeItem(
            extensionStore +
            ":" +
            key
          );

          return true;
        } catch {
          return false;
        }
      }
    },

    open:
      function (url) {
        return navigateInsideOrbit(
          url
        );
      },

    proxy:
      function (url) {
        return proxyUrlForTarget(
          url
        );
      }
  };

  /* =======================================================
     FETCH BRIDGE
  ======================================================= */

  const nativeFetch =
    window.fetch.bind(
      window
    );

  window.fetch =
    async function (
      input,
      init
    ) {
      let originalUrl;

      try {
        if (
          typeof input ===
          "string"
        ) {
          originalUrl =
            resolveTargetUrl(
              input
            );
        } else if (
          input &&
          input.url
        ) {
          originalUrl =
            resolveTargetUrl(
              input.url
            );
        }
      } catch {}

      if (
        originalUrl &&
        isHttpUrl(originalUrl) &&
        !isProxyUrl(originalUrl)
      ) {
        const proxied =
          proxyUrlForTarget(
            originalUrl
          );

        if (proxied) {
          input =
            typeof input ===
            "string"
              ? proxied
              : new Request(
                  proxied,
                  input
                );
        }
      }

      const response =
        await nativeFetch(
          input,
          init
        );

      try {
        await orbitCachePut(
          response.url ||
            input,
          response
        );
      } catch {}

      return response;
    };

  /* =======================================================
     XHR BRIDGE
  ======================================================= */

  const NativeXHR =
    window.XMLHttpRequest;

  if (NativeXHR) {
    const nativeOpen =
      NativeXHR.prototype.open;

    NativeXHR.prototype.open =
      function (
        method,
        url,
        async,
        user,
        password
      ) {
        let nextUrl =
          resolveTargetUrl(
            url
          );

        if (
          nextUrl &&
          isHttpUrl(nextUrl) &&
          !isProxyUrl(nextUrl)
        ) {
          const proxied =
            proxyUrlForTarget(
              nextUrl
            );

          if (proxied) {
            url = proxied;
          }
        }

        return nativeOpen.call(
          this,
          method,
          url,
          async !== false,
          user,
          password
        );
      };
  }

  /* =======================================================
     WINDOW.OPEN
     ======================================================= */

  const nativeWindowOpen =
    window.open;

  window.open =
    function (
      url,
      target,
      features
    ) {
      const resolved =
        resolveTargetUrl(
          url
        );

      if (
        resolved &&
        isHttpUrl(resolved)
      ) {
        const proxy =
          proxyUrlForTarget(
            resolved
          );

        if (proxy) {
          /*
           * IMPORTANT:
           * Never create a new browser tab/window.
           * Everything goes into the current
           * Orbit/Render tab.
           */
          window.location.assign(
            proxy
          );

          return window;
        }
      }

      /*
       * Non-http URLs are left alone.
       */
      if (
        typeof nativeWindowOpen ===
        "function"
      ) {
        return nativeWindowOpen.call(
          window,
          url,
          "_self",
          features
        );
      }

      return window;
    };

  /* =======================================================
     ANCHORS
  ======================================================= */

  function rewriteAnchor(
    anchor
  ) {
    if (!anchor) {
      return;
    }

    /*
     * Force every target to same tab.
     */
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

    if (
      raw.startsWith("#") ||
      raw.startsWith(
        "javascript:"
      ) ||
      raw.startsWith(
        "mailto:"
      ) ||
      raw.startsWith(
        "tel:"
      )
    ) {
      return;
    }

    const resolved =
      resolveTargetUrl(
        raw
      );

    if (
      !resolved ||
      !isHttpUrl(resolved)
    ) {
      return;
    }

    if (
      !isProxyUrl(resolved)
    ) {
      const proxy =
        proxyUrlForTarget(
          resolved
        );

      if (proxy) {
        anchor.setAttribute(
          "href",
          proxy
        );
      }
    }
  }

  function rewriteAnchors(
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
      rewriteAnchor(root);
    }

    root
      .querySelectorAll("a")
      .forEach(
        rewriteAnchor
      );
  }

  /* =======================================================
     FORMS
  ======================================================= */

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
      );

    if (!raw) {
      return;
    }

    const resolved =
      resolveTargetUrl(
        raw
      );

    if (
      !resolved ||
      !isHttpUrl(resolved)
    ) {
      return;
    }

    if (
      !isProxyUrl(resolved)
    ) {
      const proxy =
        proxyUrlForTarget(
          resolved
        );

      if (proxy) {
        form.setAttribute(
          "action",
          proxy
        );
      }
    }
  }

  function rewriteForms(
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
      root.matches("form")
    ) {
      rewriteForm(root);
    }

    root
      .querySelectorAll("form")
      .forEach(
        rewriteForm
      );
  }

  /* =======================================================
     CLICK INTERCEPTION
  ======================================================= */

  document.addEventListener(
    "click",
    function (event) {
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

      /*
       * Always same tab.
       */
      anchor.setAttribute(
        "target",
        "_self"
      );

      /*
       * For normal HTTP(S) links,
       * ensure they remain inside Orbit.
       */
      const href =
        anchor.getAttribute(
          "href"
        );

      const resolved =
        resolveTargetUrl(
          href
        );

      if (
        resolved &&
        isHttpUrl(resolved) &&
        !isProxyUrl(resolved)
      ) {
        const proxy =
          proxyUrlForTarget(
            resolved
          );

        if (proxy) {
          event.preventDefault();
          event.stopPropagation();

          window.location.assign(
            proxy
          );
        }
      }
    },
    true
  );

  /* =======================================================
     AUXCLICK / MIDDLE CLICK
  ======================================================= */

  document.addEventListener(
    "auxclick",
    function (event) {
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

      const resolved =
        resolveTargetUrl(
          href
        );

      if (
        resolved &&
        isHttpUrl(resolved)
      ) {
        const proxy =
          proxyUrlForTarget(
            resolved
          );

        if (proxy) {
          event.preventDefault();
          event.stopPropagation();

          window.location.assign(
            proxy
          );
        }
      }
    },
    true
  );

  /* =======================================================
     FORM SUBMIT
  ======================================================= */

  document.addEventListener(
    "submit",
    function (event) {
      const form =
        event.target;

      if (!form) {
        return;
      }

      rewriteForm(form);

      form.setAttribute(
        "target",
        "_self"
      );

      const action =
        form.getAttribute(
          "action"
        );

      if (!action) {
        return;
      }

      const resolved =
        resolveTargetUrl(
          action
        );

      if (
        resolved &&
        isHttpUrl(resolved) &&
        !isProxyUrl(resolved)
      ) {
        const proxy =
          proxyUrlForTarget(
            resolved
          );

        if (proxy) {
          form.setAttribute(
            "action",
            proxy
          );
        }
      }
    },
    true
  );

  /* =======================================================
     MUTATION OBSERVER
  ======================================================= */

  function observeDOM() {
    if (
      typeof MutationObserver ===
      "undefined"
    ) {
      return;
    }

    const observer =
      new MutationObserver(
        function (mutations) {
          for (
            const mutation of mutations
          ) {
            for (
              const node of mutation.addedNodes
            ) {
              if (
                node.nodeType === 1
              ) {
                rewriteAnchors(
                  node
                );

                rewriteForms(
                  node
                );
              }
            }
          }
        }
      );

    if (document.documentElement) {
      observer.observe(
        document.documentElement,
        {
          childList: true,
          subtree: true
        }
      );
    }
  }

  /* =======================================================
     HISTORY
  ======================================================= */

  const nativePushState =
    history.pushState.bind(
      history
    );

  const nativeReplaceState =
    history.replaceState.bind(
      history
    );

  history.pushState =
    function (
      state,
      title,
      url
    ) {
      let next =
        url == null
          ? null
          : resolveTargetUrl(
              url
            );

      if (
        next &&
        isHttpUrl(next) &&
        !isProxyUrl(next)
      ) {
        const proxy =
          proxyUrlForTarget(
            next
          );

        if (proxy) {
          url = proxy;
        }
      }

      return nativePushState(
        state,
        title,
        url
      );
    };

  history.replaceState =
    function (
      state,
      title,
      url
    ) {
      let next =
        url == null
          ? null
          : resolveTargetUrl(
              url
            );

      if (
        next &&
        isHttpUrl(next) &&
        !isProxyUrl(next)
      ) {
        const proxy =
          proxyUrlForTarget(
            next
          );

        if (proxy) {
          url = proxy;
        }
      }

      return nativeReplaceState(
        state,
        title,
        url
      );
    };

  /* =======================================================
     INITIAL DOM
  ======================================================= */

  function initialize() {
    rewriteAnchors(
      document
    );

    rewriteForms(
      document
    );

    observeDOM();

    /*
     * Re-run shortly after dynamic
     * application initialization.
     */
    setTimeout(
      function () {
        rewriteAnchors(
          document
        );

        rewriteForms(
          document
        );
      },
      100
    );

    setTimeout(
      function () {
        rewriteAnchors(
          document
        );

        rewriteForms(
          document
        );
      },
      1000
    );
  }

  if (
    document.readyState ===
    "loading"
  ) {
    document.addEventListener(
      "DOMContentLoaded",
      initialize,
      {
        once: true
      }
    );
  } else {
    initialize();
  }

  /* =======================================================
     CUSTOM INJECTION AUTO RUN
  ======================================================= */

  window.__ORBIT_RUN_EXTENSION__ =
    function (code) {
      if (
        typeof code !==
        "string"
      ) {
        return;
      }

      try {
        const fn =
          new Function(
            "OrbitSource",
            "OrbitExtension",
            code
          );

        return fn(
          window.OrbitSource,
          window.OrbitExtension
        );
      } catch (error) {
        console.error(
          "Orbit extension error:",
          error
        );
      }
    };

})();
</script>
`;
}

/* =========================================================
   HTML REWRITE
========================================================= */

function rewriteHTML(
  html,
  targetUrl,
  sid,
  injection
) {
  let output =
    String(html);

  /*
   * Force all target attributes to _self.
   *
   * This prevents normal HTML target="_blank",
   * target="new", target="popup", etc.
   */
  output =
    output.replace(
      /(\s)target\s*=\s*(["'])[^"']*\2/gi,
      '$1target="_self"'
    );

  /*
   * Rewrite URLs in HTML attributes.
   */
  const attributes = [
    "href",
    "src",
    "action",
    "poster",
    "data-src",
    "data-href",
    "data-url",
    "formaction"
  ];

  for (
    const attribute of attributes
  ) {
    const regex =
      new RegExp(
        "(" +
          attribute +
          "\\s*=\\s*[\"'])" +
          "([^\"']+)" +
          "([\"'])",
        "gi"
      );

    output =
      output.replace(
        regex,
        function (
          full,
          prefix,
          value,
          suffix
        ) {
          if (
            shouldSkipUrl(
              value
            )
          ) {
            return full;
          }

          const resolved =
            absolute(
              value,
              targetUrl
            );

          if (
            !resolved ||
            !isHttpUrl(resolved)
          ) {
            return full;
          }

          return (
            prefix +
            proxyUrl(
              resolved,
              sid
            ) +
            suffix
          );
        }
      );
  }

  /*
   * Rewrite srcset.
   */
  output =
    output.replace(
      /(srcset\s*=\s*["'])([^"']+)(["'])/gi,
      function (
        full,
        prefix,
        value,
        suffix
      ) {
        const parts =
          value.split(",");

        const rewritten =
          parts.map(
            function (part) {
              const trimmed =
                part.trim();

              if (!trimmed) {
                return part;
              }

              const pieces =
                trimmed.split(
                  /\s+/
                );

              const url =
                pieces.shift();

              if (
                shouldSkipUrl(
                  url
                )
              ) {
                return part;
              }

              const resolved =
                absolute(
                  url,
                  targetUrl
                );

              if (
                !resolved ||
                !isHttpUrl(
                  resolved
                )
              ) {
                return part;
              }

              return [
                proxyUrl(
                  resolved,
                  sid
                ),
                ...pieces
              ].join(" ");
            }
          );

        return (
          prefix +
          rewritten.join(", ") +
          suffix
        );
      }
    );

  /*
   * Rewrite CSS url(...).
   */
  output =
    output.replace(
      /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
      function (
        full,
        quote,
        value
      ) {
        if (
          shouldSkipUrl(
            value
          )
        ) {
          return full;
        }

        const resolved =
          absolute(
            value,
            targetUrl
          );

        if (
          !resolved ||
          !isHttpUrl(resolved)
        ) {
          return full;
        }

        return (
          "url(" +
          quote +
          proxyUrl(
            resolved,
            sid
          ) +
          quote +
          ")"
        );
      }
    );

  /*
   * Add bridge before </head>.
   */
  const bridge =
    buildBridge(
      sid,
      targetUrl
    );

  if (
    /<\/head\s*>/i.test(
      output
    )
  ) {
    output =
      output.replace(
        /<\/head\s*>/i,
        bridge +
        "</head>"
      );
  } else {
    output =
      bridge +
      output;
  }

  /*
   * Add custom injection.
   */
  if (
    typeof injection ===
      "string" &&
    injection.trim()
  ) {
    const escaped =
      JSON.stringify(
        injection
      );

    const runner =
      `<script>
(function(){
  try {
    window.__ORBIT_RUN_EXTENSION__(${escaped});
  } catch(e) {
    console.error("Orbit injection error:", e);
  }
})();
</script>`;

    if (
      /<\/body\s*>/i.test(
        output
      )
    ) {
      output =
        output.replace(
          /<\/body\s*>/i,
          runner +
          "</body>"
        );
    } else {
      output += runner;
    }
  }

  return output;
}

/* =========================================================
   HANDLE PROXY
========================================================= */

async function handleProxy(
  req,
  res,
  targetUrl,
  sid
) {
  const session =
    sessions.get(sid);

  if (!session) {
    return res
      .status(404)
      .send(
        "Missing proxy session"
      );
  }

  if (
    !isHttpUrl(targetUrl)
  ) {
    return res
      .status(400)
      .send(
        "Invalid target URL"
      );
  }

  const navigation =
    isNavigationRequest(
      req
    );

  if (navigation) {
    const allowed =
      navigationAllowed(
        session
      );

    if (!allowed.ok) {
      return res
        .status(429)
        .type("text/plain")
        .send(
          "Daily navigation limit reached."
        );
    }
  }

  const started =
    Date.now();

  try {
    const response =
      await fetchTarget(
        targetUrl,
        req,
        sid
      );

    saveCookies(
      response,
      session,
      targetUrl
    );

    /*
     * Charge only the actual elapsed
     * navigation time.
     *
     * There is NO navigation cooldown.
     */
    if (navigation) {
      chargeNavigation(
        session,
        Date.now() - started
      );
    }

    /*
     * Redirect handling.
     *
     * Never allow a target redirect to
     * escape the Orbit proxy.
     */
    if (
      response.status >= 300 &&
      response.status < 400
    ) {
      const location =
        response.headers.get(
          "location"
        );

      if (location) {
        const absoluteLocation =
          absolute(
            location,
            targetUrl
          );

        if (
          absoluteLocation &&
          isHttpUrl(
            absoluteLocation
          )
        ) {
          res.status(
            response.status
          );

          copyResponseHeaders(
            response,
            res
          );

          res.setHeader(
            "Location",
            proxyUrl(
              absoluteLocation,
              sid
            )
          );

          return res.end();
        }
      }
    }

    copyResponseHeaders(
      response,
      res
    );

    const contentType =
      String(
        response.headers.get(
          "content-type"
        ) || ""
      ).toLowerCase();

    if (
      contentType.includes(
        "text/html"
      )
    ) {
      const buffer =
        Buffer.from(
          await response.arrayBuffer()
        );

      const html =
        buffer.toString(
          "utf8"
        );

      const rewritten =
        rewriteHTML(
          html,
          targetUrl,
          sid,
          session.injection
        );

      res.status(
        response.status
      );

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      res.setHeader(
        "Cache-Control",
        "private, no-store"
      );

      return res.send(
        rewritten
      );
    }

    res.status(
      response.status
    );

    return streamResponse(
      response,
      res
    );
  } catch (error) {
    return res
      .status(502)
      .type("text/plain")
      .send(
        "Proxy fetch failed: " +
        error.message
      );
  }
}

/* =========================================================
   OPEN
========================================================= */

app.get(
  "/open",
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
      sessions.get(
        sid
      );

    const allowed =
      navigationAllowed(
        session
      );

    if (!allowed.ok) {
      return res
        .status(429)
        .send(
          "Daily navigation limit reached."
        );
    }

    setSessionCookie(
      res,
      sid
    );

    return handleProxy(
      req,
      res,
      target,
      sid
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
      return res.json({
        active: false
      });
    }

    const session =
      found.session;

    resetBudgetIfNeeded(
      session
    );

    return res.json({
      active: true,

      sid:
        found.sid,

      target:
        session.target,

      created:
        session.created,

      usedMs:
        session.usedMs,

      remainingMs:
        remainingBudget(
          session
        ),

      remainingSeconds:
        Math.floor(
          remainingBudget(
            session
          ) / 1000
        )
    });
  }
);

/* =========================================================
   PROXY BY SESSION + ENCODED URL
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
      !sid ||
      !sessions.has(sid)
    ) {
      return res
        .status(404)
        .send(
          "Missing proxy session"
        );
    }

    let target;

    try {
      target =
        decode(
          req.params.encoded
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid encoded URL"
        );
    }

    if (
      !isHttpUrl(target)
    ) {
      return res
        .status(400)
        .send(
          "Invalid target URL"
        );
    }

    return handleProxy(
      req,
      res,
      target,
      sid
    );
  }
);

/* =========================================================
   PROXY BY URL
========================================================= */

app.all(
  "/proxy",
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

    let found =
      getSession(req);

    let sid;

    if (!found) {
      sid =
        createSession(
          target
        );

      found = {
        sid,
        session:
          sessions.get(
            sid
          )
      };
    } else {
      sid =
        found.sid;
    }

    setSessionCookie(
      res,
      sid
    );

    return handleProxy(
      req,
      res,
      target,
      sid
    );
  }
);

/* =========================================================
   RESULTS
========================================================= */

app.all(
  "/results",
  async (
    req,
    res
  ) => {
    let found =
      getSession(req);

    let sid;

    if (!found) {
      /*
       * Compatibility fallback.
       *
       * If no session exists, create one
       * from the supplied url or a neutral
       * target.
       */
      const requested =
        req.query.url ||
        "https://www.google.com/";

      if (
        !isHttpUrl(
          requested
        )
      ) {
        return res
          .status(400)
          .send(
            "Missing proxy session"
          );
      }

      sid =
        createSession(
          requested
        );

      found = {
        sid,
        session:
          sessions.get(
            sid
          )
      };
    } else {
      sid =
        found.sid;
    }

    const session =
      found.session;

    let original;

    try {
      original =
        new URL(
          session.target
        );
    } catch {
      return res
        .status(400)
        .send(
          "Invalid session target"
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

    /*
     * IMPORTANT:
     * /results is intentionally retained.
     *
     * It maps to the target origin's
     * /results endpoint.
     */
    const target =
      new URL(
        "/results" +
        query,
        original.origin
      ).href;

    setSessionCookie(
      res,
      sid
    );

    return handleProxy(
      req,
      res,
      target,
      sid
    );
  }
);

/* =========================================================
   WATCH
========================================================= */

app.all(
  "/watch",
  async (
    req,
    res
  ) => {
    let found =
      getSession(req);

    let sid;

    if (!found) {
      return res
        .status(400)
        .send(
          "Missing proxy session"
        );
    }

    sid =
      found.sid;

    const session =
      found.session;

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
   DYNAMIC PATH
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
     * Session-bound.
     * Not an anonymous open proxy.
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

      /*
       * RAW source:
       * no HTML rewriting,
       * no bridge,
       * no extension.
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

      navigationCooldown:
        false,

      features: [
        "dynamic URL proxy",
        "isolated sessions",
        "isolated target cookies",
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
