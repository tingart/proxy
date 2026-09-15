const express = require("express");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const PORT = process.env.PORT || 3000;

const MAX_SIZE = 15 * 1024 * 1024;
const TIMEOUT = 20000;

function isPrivateIP(ip) {
    if (net.isIPv4(ip)) {
        const p = ip.split(".").map(Number);
        return (
            p[0] === 10 ||
            p[0] === 127 ||
            (p[0] === 169 && p[1] === 254) ||
            (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
            (p[0] === 192 && p[1] === 168) ||
            p[0] === 0
        );
    }

    if (net.isIPv6(ip)) {
        const x = ip.toLowerCase();
        return (
            x === "::1" ||
            x.startsWith("fc") ||
            x.startsWith("fd") ||
            x.startsWith("fe80:")
        );
    }

    return true;
}

async function validateTarget(target) {
    let url;

    try {
        url = new URL(target);
    } catch {
        throw new Error("Invalid URL");
    }

    if (!["http:", "https:"].includes(url.protocol)) {
        throw new Error("Only HTTP/HTTPS URLs are allowed");
    }

    const addresses = await dns.lookup(url.hostname, { all: true });

    for (const address of addresses) {
        if (isPrivateIP(address.address)) {
            throw new Error("Private/internal target blocked");
        }
    }

    return url;
}

app.get("/", (req, res) => {
    res.json({
        name: "Orbit Source Proxy",
        status: "online",
        usage: "/source?url=https://example.com"
    });
});

app.get("/source", async (req, res) => {
    const target = req.query.url;

    if (!target) {
        return res.status(400).send("Missing ?url=");
    }

    let url;

    try {
        url = await validateTarget(target);
    } catch (err) {
        return res.status(400).send(err.message);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT);

    try {
        const response = await fetch(url, {
            method: "GET",
            redirect: "follow",
            signal: controller.signal,
            headers: {
                "User-Agent":
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/150 Safari/537.36",
                "Accept":
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        });

        clearTimeout(timer);

        if (!response.ok) {
            return res
                .status(response.status)
                .send(`Target returned HTTP ${response.status}`);
        }

        const contentType =
            response.headers.get("content-type") ||
            "application/octet-stream";

        const contentLength =
            Number(response.headers.get("content-length")) || 0;

        if (contentLength > MAX_SIZE) {
            return res.status(413).send("Response too large");
        }

        res.setHeader("Content-Type", contentType);
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Cache-Control", "no-store");

        if (!response.body) {
            return res.end();
        }

        const reader = response.body.getReader();
        let received = 0;

        while (true) {
            const { value, done } = await reader.read();

            if (done) break;

            received += value.byteLength;

            if (received > MAX_SIZE) {
                await reader.cancel();
                return res.status(413).end("Response too large");
            }

            if (!res.write(Buffer.from(value))) {
                await new Promise(resolve =>
                    res.once("drain", resolve)
                );
            }
        }

        res.end();

    } catch (err) {
        clearTimeout(timer);

        if (!res.headersSent) {
            res.status(502).send(
                err.name === "AbortError"
                    ? "Target request timed out"
                    : "Proxy error: " + err.message
            );
        } else {
            res.end();
        }
    }
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Orbit Source Proxy running on port ${PORT}`);
});
