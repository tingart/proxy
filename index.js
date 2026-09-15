const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_SIZE = 20 * 1024 * 1024;
const TIMEOUT = 30000;

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "*");
    next();
});

function makeProxyUrl(url) {
    return "/proxy?url=" + encodeURIComponent(url);
}

function rewriteHtml(html, baseUrl) {
    const origin = new URL(baseUrl).origin;

    // href
    html = html.replace(
        /(\bhref\s*=\s*["'])([^"']+)(["'])/gi,
        (m, a, url, c) => {
            if (
                url.startsWith("#") ||
                url.startsWith("javascript:") ||
                url.startsWith("data:") ||
                url.startsWith("mailto:")
            ) return m;

            try {
                const absolute = new URL(url, baseUrl).href;
                return a + makeProxyUrl(absolute) + c;
            } catch {
                return m;
            }
        }
    );

    // src
    html = html.replace(
        /(\bsrc\s*=\s*["'])([^"']+)(["'])/gi,
        (m, a, url, c) => {
            if (
                url.startsWith("data:") ||
                url.startsWith("blob:") ||
                url.startsWith("#")
            ) return m;

            try {
                const absolute = new URL(url, baseUrl).href;
                return a + makeProxyUrl(absolute) + c;
            } catch {
                return m;
            }
        }
    );

    // form action
    html = html.replace(
        /(\baction\s*=\s*["'])([^"']+)(["'])/gi,
        (m, a, url, c) => {
            try {
                const absolute = new URL(url, baseUrl).href;
                return a + makeProxyUrl(absolute) + c;
            } catch {
                return m;
            }
        }
    );

    // CSS url(...)
    html = html.replace(
        /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
        (m, quote, url) => {
            if (
                url.startsWith("data:") ||
                url.startsWith("#") ||
                url.startsWith("http://") ||
                url.startsWith("https://")
            ) {
                return m;
            }

            try {
                const absolute = new URL(url, baseUrl).href;
                return `url("${makeProxyUrl(absolute)}")`;
            } catch {
                return m;
            }
        }
    );

    // Keep absolute URLs pointing at the same site inside the proxy too.
    const escapedOrigin = origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    html = html.replace(
        new RegExp(`(["'])(${escapedOrigin})(/[^"']*)(["'])`, "gi"),
        (m, q1, site, path, q2) => {
            const absolute = site + path;
            return q1 + makeProxyUrl(absolute) + q2;
        }
    );

    return html;
}

async function fetchTarget(targetUrl, req, res) {
    let url;

    try {
        url = new URL(targetUrl);
    } catch {
        return res.status(400).send("Invalid target URL");
    }

    if (!["http:", "https:"].includes(url.protocol)) {
        return res.status(400).send("Only HTTP/HTTPS URLs are allowed");
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT);

    try {
        const headers = {
            "User-Agent":
                req.headers["user-agent"] ||
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/150 Safari/537.36",
            "Accept":
                req.headers["accept"] ||
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        };

        if (req.headers.cookie) {
            headers.Cookie = req.headers.cookie;
        }

        const response = await fetch(url.href, {
            method: "GET",
            headers,
            redirect: "follow",
            signal: controller.signal
        });

        clearTimeout(timer);

        const contentType =
            response.headers.get("content-type") ||
            "application/octet-stream";

        const finalUrl = response.url || url.href;

        // Redirect through our proxy instead of sending the target URL directly.
        if (response.redirected) {
            return res.redirect(302, makeProxyUrl(finalUrl));
        }

        const length = Number(response.headers.get("content-length") || 0);

        if (length > MAX_SIZE) {
            return res.status(413).send("Response too large");
        }

        res.setHeader("Content-Type", contentType);
        res.setHeader("Cache-Control", "no-store");

        // Do not forward iframe-blocking headers.
        // Also don't forward upstream CORS policy.
        const blocked = new Set([
            "content-security-policy",
            "content-security-policy-report-only",
            "x-frame-options",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "content-encoding",
            "content-length"
        ]);

        for (const [key, value] of response.headers) {
            if (!blocked.has(key.toLowerCase())) {
                if (key.toLowerCase() === "set-cookie") {
                    res.append("Set-Cookie", value);
                } else {
                    res.setHeader(key, value);
                }
            }
        }

        if (!response.body) {
            return res.end();
        }

        const reader = response.body.getReader();

        // HTML gets rewritten so navigation/resources stay inside proxy.
        if (contentType.toLowerCase().includes("text/html")) {
            const chunks = [];
            let total = 0;

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                total += value.byteLength;

                if (total > MAX_SIZE) {
                    await reader.cancel();
                    return res.status(413).send("Response too large");
                }

                chunks.push(Buffer.from(value));
            }

            const html = Buffer.concat(chunks).toString("utf8");
            const rewritten = rewriteHtml(html, finalUrl);

            return res.send(rewritten);
        }

        // Stream everything else.
        let total = 0;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            total += value.byteLength;

            if (total > MAX_SIZE) {
                await reader.cancel();
                return res.status(413).end("Response too large");
            }

            if (!res.write(Buffer.from(value))) {
                await new Promise(resolve => res.once("drain", resolve));
            }
        }

        res.end();

    } catch (error) {
        clearTimeout(timer);

        if (!res.headersSent) {
            res.status(502).send(
                error.name === "AbortError"
                    ? "Target request timed out"
                    : "Proxy error: " + error.message
            );
        } else {
            res.end();
        }
    }
}

// Original entry point
app.get("/source", async (req, res) => {
    if (!req.query.url) {
        return res.status(400).send("Missing ?url=");
    }

    await fetchTarget(req.query.url, req, res);
});

// Rewritten links/resources/navigation arrive here.
app.get("/proxy", async (req, res) => {
    if (!req.query.url) {
        return res.status(400).send("Missing ?url=");
    }

    await fetchTarget(req.query.url, req, res);
});

app.get("/", (req, res) => {
    res.json({
        name: "Orbit Source Proxy",
        status: "online",
        usage: "/source?url=https://example.com"
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log("Orbit Source Proxy running on port " + PORT);
});
