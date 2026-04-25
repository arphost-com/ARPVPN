const RRD_WINDOWS = ["24h", "6h", "7d", "30d"];
const PREFETCH_MAX_CONNECTIONS = 32;
const PREFETCH_MAX_REQUESTS = 24;
const PREFETCH_DELAY_MS = 1500;
const PREFETCH_BETWEEN_REQUEST_MS = 700;
const PREFETCH_SESSION_TTL_MS = 15 * 60 * 1000;
const SESSION_CACHE_KEY = "arpvpn_rrd_prefetch_seen";
const RRD_LINK_PATH_RE = /^\/traffic\/rrd\/([a-f0-9]{32})$/;

function readSessionCache() {
    try {
        const raw = window.sessionStorage.getItem(SESSION_CACHE_KEY);
        if (!raw) {
            return {};
        }
        const parsed = JSON.parse(raw);
        if (typeof parsed === "object" && parsed !== null) {
            return parsed;
        }
    } catch (_error) {
        // Ignore corrupt or unavailable session cache.
    }
    return {};
}

function writeSessionCache(cache) {
    try {
        window.sessionStorage.setItem(SESSION_CACHE_KEY, JSON.stringify(cache));
    } catch (_error) {
        // Ignore write failures (private mode/full storage).
    }
}

function normalizeUrl(url) {
    return `${url.pathname}${url.search}`;
}

function discoverConnectionIds() {
    const ids = new Set();
    const links = document.querySelectorAll("a[href*='/traffic/rrd/']");
    for (const link of links) {
        let href;
        try {
            href = new URL(link.href, window.location.origin);
        } catch (_error) {
            continue;
        }
        const match = href.pathname.match(RRD_LINK_PATH_RE);
        if (match) {
            ids.add(match[1]);
        }
        if (ids.size >= PREFETCH_MAX_CONNECTIONS) {
            break;
        }
    }
    return [...ids];
}

function collectVisibleImageUrls() {
    const urls = new Set();
    const imgs = document.querySelectorAll("img[src*='/traffic/rrd/']");
    for (const img of imgs) {
        try {
            const parsed = new URL(img.src, window.location.origin);
            urls.add(normalizeUrl(parsed));
        } catch (_error) {
            // Skip malformed sources.
        }
    }
    return urls;
}

function buildQueue(connectionIds) {
    const existingUrls = collectVisibleImageUrls();
    const sessionCache = readSessionCache();
    const now = Date.now();
    const queue = [];

    for (const connectionId of connectionIds) {
        for (const windowName of RRD_WINDOWS) {
            const url = new URL(`/traffic/rrd/${connectionId}.png`, window.location.origin);
            url.searchParams.set("window", windowName);
            const key = normalizeUrl(url);

            const lastSeen = Number(sessionCache[key] || 0);
            if (existingUrls.has(key) || (now - lastSeen) < PREFETCH_SESSION_TTL_MS) {
                continue;
            }
            queue.push({ key, href: url.href });
        }
    }

    return { queue: queue.slice(0, PREFETCH_MAX_REQUESTS), sessionCache };
}

function prefetchImage(url) {
    return new Promise((resolve) => {
        const img = new Image();
        img.onload = resolve;
        img.onerror = resolve;
        img.src = url;
    });
}

async function runQueue(queue, sessionCache) {
    if (!queue.length) {
        return;
    }

    // Trickle prefetch to avoid network spikes on production.
    for (const next of queue) {
        await prefetchImage(next.href);
        sessionCache[next.key] = Date.now();
        if (PREFETCH_BETWEEN_REQUEST_MS > 0) {
            await new Promise((resolve) => window.setTimeout(resolve, PREFETCH_BETWEEN_REQUEST_MS));
        }
    }
    writeSessionCache(sessionCache);
}

async function startBackgroundPrefetch() {
    if (window.location.pathname.startsWith("/traffic/rrd/")) {
        return;
    }
    const connectionIds = discoverConnectionIds();
    if (!connectionIds.length) {
        return;
    }
    const { queue, sessionCache } = buildQueue(connectionIds);
    await runQueue(queue, sessionCache);
}

function schedulePrefetch() {
    const run = () => {
        window.setTimeout(() => {
            startBackgroundPrefetch().catch(() => {
                // No-op: prefetch should never break the page.
            });
        }, PREFETCH_DELAY_MS);
    };

    if ("requestIdleCallback" in window) {
        window.requestIdleCallback(run, { timeout: 4000 });
    } else {
        run();
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", schedulePrefetch, { once: true });
} else {
    schedulePrefetch();
}
