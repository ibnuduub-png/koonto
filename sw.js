const CACHE = 'baraka-receipt-v116';
const CORE = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png', './icon-maskable-512.png', './icon-180.png'];
const FONT_CSS = 'https://fonts.googleapis.com/css2?family=Patrick+Hand&family=Caveat&family=Kalam&family=Shadows+Into+Light&family=Indie+Flower&family=Gochi+Hand&family=Covered+By+Your+Grace&family=Homemade+Apple&family=Nanum+Pen+Script&family=Reenie+Beanie&family=Dancing+Script&family=Roboto&family=Open+Sans&family=Lato&family=Montserrat&family=Nunito:wght@400;600;700;800&family=Source+Sans+3&family=Merriweather&family=Courier+Prime&family=Roboto+Mono&family=Inter:wght@400;700&family=Poppins:wght@400;700&family=Work+Sans:wght@400;700&family=IBM+Plex+Sans:wght@400;700&family=DM+Sans:wght@400;700&family=Libre+Franklin:wght@400;700&family=Oswald:wght@400;700&family=Carlito:wght@400;700&family=Caladea:wght@400;700&family=Arimo:wght@400;700&family=Tinos:wght@400;700&family=Cousine:wght@400;700&family=EB+Garamond:wght@400;700&family=Bodoni+Moda:wght@400;700&family=Cabin:wght@400;700&family=Playfair+Display:wght@400;700&family=Libre+Baskerville:wght@400;700&family=Lora:wght@400;700&family=PT+Serif:wght@400;700&family=IBM+Plex+Mono:wght@400;700&display=swap';

async function cacheFonts(cache) {
  // Download the handwriting font itself (not just its stylesheet) so it works offline
  try {
    const res = await fetch(FONT_CSS);
    if (!res.ok) return;
    const css = await res.clone().text();
    await cache.put(FONT_CSS, res);
    let urls = [...css.matchAll(/\/\*\s*latin\s*\*\/\s*@font-face\s*\{[^}]*?url\((https:[^)]+)\)/g)].map(m => m[1]);
    if (!urls.length) urls = [...css.matchAll(/url\((https:[^)]+)\)/g)].map(m => m[1]);
    await Promise.all(urls.map(u => cache.add(u).catch(() => {})));
  } catch (_) {}
}

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await c.addAll(CORE);
    try { await c.add('./fonts/patrick-hand.woff2'); } catch (_) {}   // optional self-hosted font
    await cacheFonts(c);
    self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
    await self.clients.claim();
    // retry font download if the install happened without the font
    const c = await caches.open(CACHE);
    if (!(await c.match(FONT_CSS))) cacheFonts(c);
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const u = new URL(req.url);
  // Only fonts are cached from other sites; Google sign-in and Drive calls must go straight to the network
  if (u.origin !== self.location.origin && !/(^|\.)(fonts\.googleapis\.com|fonts\.gstatic\.com)$/.test(u.hostname)) return;
  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const sameOrigin = new URL(req.url).origin === self.location.origin;
    if (sameOrigin) {
      // App files: fresh copy when online, saved copy when offline
      try {
        const res = await fetch(req, { cache: 'no-cache' });
        if (res && res.ok) cache.put(req, res.clone());
        return res;
      } catch (_) {
        const hit = await cache.match(req, { ignoreSearch: req.mode === 'navigate' });
        if (hit) return hit;
        if (req.mode === 'navigate') return (await cache.match('./index.html')) || Response.error();
        return Response.error();
      }
    }
    // Fonts: saved copy first, refresh in background when online
    const hit = await cache.match(req);
    const net = fetch(req).then(res => {
      if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone());
      return res;
    }).catch(() => null);
    if (hit) { e.waitUntil(net); return hit; }
    return (await net) || Response.error();
  })());
});
