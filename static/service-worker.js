const CACHE_NAME = "phishguard-v1";

const STATIC_FILES = [
    "/static/style.css",
    "/static/icon-192.png",
    "/static/icon-512.png"
];

self.addEventListener("install", event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_FILES);
        })
    );

    self.skipWaiting();
});

self.addEventListener("activate", event => {
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys
                    .filter(key => key !== CACHE_NAME)
                    .map(key => caches.delete(key))
            );
        })
    );

    self.clients.claim();
});

self.addEventListener("fetch", event => {
    const url = new URL(event.request.url);

    // Never cache scans or their results.
    if (url.pathname === "/scan") {
        return;
    }

    // Cache static files, but use the network for everything else.
    if (url.pathname.startsWith("/static/")) {
        event.respondWith(
            caches.match(event.request).then(cached => {
                return cached || fetch(event.request);
            })
        );
    }
});
