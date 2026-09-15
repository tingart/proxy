const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

const MAX_SIZE = 20 * 1024 * 1024;
const TIMEOUT = 30000;

// Allow Orbit frontend to call the proxy.
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

// Keep request bodies available for POST requests.
app.use(express.raw({ type: "*/*", limit: "10mb" }));

function proxyUrl(url) {
    return "/proxy?url=" + encodeURIComponent(url);
}

function absoluteUrl(value, base) {
    try {
        if (
            !value ||
            value.startsWith("#") ||
            value.startsWith("data:") ||
            value.startsWith("blob:") ||
            value.startsWith("javascript:") ||
            value.startsWith("mailto:")
        ) {
            return null;
        }

        return new URL(value, base).href;
    } catch {
        return null;
    }
}

function rewriteAttribute(html, attribute, baseUrl) {
    const regex = new RegExp(
        `(${attribute}\\s*=\\s*["'])([^"']+)(["'])`,
        "gi"
    );

    return html.replace(regex, (full, start, value, end) => {
        const absolute = absoluteUrl(value, baseUrl);

        if (!absolute) return full;

        return start + proxyUrl(absolute) + end;
    });
}

function rewriteSrcSet(html, baseUrl) {
    return html.replace(
        /(\bsrcset\s*=\s*["'])([^"']+)(["'])/gi,
        (full, start, value, end) => {
            const parts = value.split(",");

            const rewritten = parts.map(part => {
                const pieces = part.trim().split(/\s+/);
                const url = absoluteUrl(pieces[0], baseUrl);

                if (!url) return part;

                pieces[0] = proxyUrl(url);
                return pieces.join(" ");
            });

            return start + rewritten.join(", ") + end;
        }
    );
}

function rewriteCss(html, baseUrl) {
    return html.replace(
        /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
        (full, quote, value) => {
            const absolute = absoluteUrl(value.trim(), baseUrl);

            if (!absolute) return full;

            return `url("${proxyUrl(absolute)}")`;
        }
    );
}

function injectBridge(html, baseUrl, extensionCode) {
    const bridge = `
<script>
(() => {
    const PROXY = ${JSON.stringify("/proxy?url=")};
    const BASE = ${JSON.stringify(baseUrl)};

    function route(input) {
        try {
            const value =
                typeof input === "string"
                    ? input
                    : input.url;

            const absolute = new URL(value, BASE).href;

            if (
                absolute.startsWith("http://") ||
                absolute.startsWith("https://")
            ) {
                return PROXY + encodeURIComponent(absolute);
            }

            return value;
        } catch {
            return input;
        }
    }

    // fetch()
    const originalFetch = window.fetch;

    window.fetch = function(input, init) {
        if (typeof input === "string") {
            input = route(input);
        } else if (input && input.url) {
            try {
                input = new Request(route(input.url), input);
            } catch {}
        }

        return originalFetch.call(this, input, init);
    };

    // XMLHttpRequest
    const originalOpen = XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open = function(
        method,
        url,
        async,
        user,
        password
    ) {
        return originalOpen.call(
            this,
            method,
            route(url),
            async,
            user,
            password
        );
    };
})();
</script>
`;

    let result = html;

    if (extensionCode) {
        result += `
<script>
try {
${extensionCode}
} catch (e) {
    console.error("Orbit extension error:", e);
}
</script>
`;
    }

    if (result.includes("</head>")) {
        return result.replace("</head>", bridge + "</head>");
    }

    return bridge + result;
}

function rewriteHtml(html, baseUrl, extensionCode) {
    // Normal document/resource URLs.
    for (const attr of [
        "href",
        "src",
        "action",
        "poster",
        "data",
        "formaction"
    ]) {
        html = rewriteAttribute(html, attr, baseUrl);
    }

    html = rewriteSrcSet(html, baseUrl);
    html = rewriteCss(html, baseUrl);

    return injectBridge(html, baseUrl, extensionCode);
}

function copyResponseHeaders(response, res) {
    const blocked = new Set([
        "content-length",
        "content-encoding",
        "x-frame-options",
        "content-security-policy",
        "content-security-policy-report-only",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "transfer-encoding"
    ]);

    for (const [key, value] of response.headers) {
        if (!blocked.has(key.toLowerCase())) {
            res.setHeader(key, value);
        }
    }
}

async function fetchTarget(target, req, res) {
    let targetUrl;

    try {
        targetUrl = new URL(target);
    } catch {
        return res.status(400).send("Invalid target URL");
    }

    if (!["http:", "https:"].includes(targetUrl.protocol)) {
        return res.status(400).send("Only HTTP/HTTPS URLs are allowed");
    }

    const controller = new AbortController();
    const timer = setTimeout(
        () => controller.abort(),
        TIMEOUT
    );

    try {
        const headers = {
            "User-Agent":
                req.headers["user-agent"] ||
                "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/150 Mobile Safari/537.36",

            "Accept":
                req.headers["accept"] ||
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        };

        if (req.headers.cookie) {
            headers.Cookie = req.headers.cookie;
        }

        if (req.headers.referer) {
            headers.Referer = req.headers.referer;
        }

        const options = {
            method: req.method,
            headers,
            redirect: "manual",
            signal: controller.signal
        };

        if (
            req.method !== "GET" &&
            req.method !== "HEAD" &&
            req.body &&
            req.body.length
        ) {
            options.body = req.body;
        }

        const response = await fetch(
            targetUrl.href,
            options
        );

        clearTimeout(timer);

        // Keep redirects inside our proxy.
        if (
            response.status >= 300 &&
            response.status < 400
        ) {
            const location =
                response.headers.get("location");

            if (location) {
                const destination =
                    new URL(location, targetUrl.href).href;

                return res.redirect(
                    response.status,
                    proxyUrl(destination)
                );
            }
        }

        const contentType =
            response.headers.get("content-type") ||
            "application/octet-stream";

        const length = Number(
            response.headers.get("content-length") || 0
        );

        if (length > MAX_SIZE) {
            return res
                .status(413)
                .send("Response too large");
        }

        copyResponseHeaders(response, res);

        res.setHeader(
            "Content-Type",
            contentType
        );

        res.setHeader(
            "Cache-Control",
            "no-store"
        );

        if (!response.body) {
            return res.end();
        }

        // No streaming:
        // receive the complete resource first.
        const buffer =
            Buffer.from(await response.arrayBuffer());

        if (buffer.length > MAX_SIZE) {
            return res
                .status(413)
                .send("Response too large");
        }

        // HTML is the part we modify.
        if (
            contentType
                .toLowerCase()
                .includes("text/html")
        ) {
            let html = buffer.toString("utf8");

            // Optional extension payload.
            let extensionCode = "";

            if (req.query.inject) {
                try {
                    extensionCode =
                        Buffer.from(
                            req.query.inject,
                            "base64url"
                        ).toString("utf8");
                } catch {}
            }

            html = rewriteHtml(
                html,
                targetUrl.href,
                extensionCode
            );

            return res.send(html);
        }

        // Other resources are returned untouched.
        return res.send(buffer);

    } catch (error) {
        clearTimeout(timer);

        if (!res.headersSent) {
            return res
                .status(502)
                .send(
                    error.name === "AbortError"
                        ? "Target request timed out"
                        : "Proxy error: " + error.message
                );
        }

        res.end();
    }
}

// Initial page.
app.all("/source", async (req, res) => {
    if (!req.query.url) {
        return res
            .status(400)
            .send("Missing ?url=");
    }

    await fetchTarget(
        req.query.url,
        req,
        res
    );
});

// All rewritten resources/navigation.
app.all("/proxy", async (req, res) => {
    if (!req.query.url) {
        return res
            .status(400)
            .send("Missing ?url=");
    }

    await fetchTarget(
        req.query.url,
        req,
        res
    );
});

// Status.
app.get("/", (req, res) => {
    res.json({
        name: "Orbit Source Proxy",
        status: "online",
        usage:
            "/source?url=https://example.com"
    });
});

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log(
            "Orbit Source Proxy running on port " +
            PORT
        );
    }
);
