/**
 * Daly Alpha - Service Worker
 * Provides offline functionality and caching
 */

const CACHE_NAME = 'daly-alpha-v4';
const STATIC_CACHE = 'daly-static-v4';

// Files to cache immediately
const STATIC_FILES = [
  'index.html',
  'css/styles.css',
  'js/app.js',
  'manifest.json',
  'images/camp.png',
  'images/sniper.png',
  'images/fighter.png',
  'images/cavalry.png'
];

// External resources to cache on first use
const EXTERNAL_RESOURCES = [
  'https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800;900&display=swap'
];

// Install event - cache static files
self.addEventListener('install', event => {
  console.log('[SW] Installing...');
  
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('[SW] Caching static files');
        return cache.addAll(STATIC_FILES);
      })
      .then(() => self.skipWaiting())
      .catch(err => {
        console.warn('[SW] Install failed:', err);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('[SW] Activating...');
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames
            .filter(name => name !== STATIC_CACHE && name !== CACHE_NAME)
            .map(name => {
              console.log('[SW] Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch event - serve from cache, fall back to network
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests
  if (request.method !== 'GET') return;
  
  // Skip chrome-extension and other non-http(s) requests
  if (!url.protocol.startsWith('http')) return;
  
  // Skip external API requests
  if (url.hostname.includes('googleapis.com') && url.pathname.includes('generateContent')) return;
  
  // For Tesseract.js - network first, then cache
  if (url.hostname === 'unpkg.com' && url.pathname.includes('tesseract')) {
    event.respondWith(
      fetch(request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }
  
  // For static files - cache first, then network
  if (STATIC_FILES.some(file => url.pathname.endsWith(file))) {
    event.respondWith(
      caches.match(request)
        .then(cached => {
          if (cached) return cached;
          
          return fetch(request)
            .then(response => {
              if (response.ok) {
                const clone = response.clone();
                caches.open(STATIC_CACHE).then(cache => cache.put(request, clone));
              }
              return response;
            });
        })
    );
    return;
  }
  
  // For Google Fonts - cache first
  if (url.hostname.includes('fonts.googleapis.com') || url.hostname.includes('fonts.gstatic.com')) {
    event.respondWith(
      caches.match(request)
        .then(cached => {
          if (cached) return cached;
          
          return fetch(request)
            .then(response => {
              if (response.ok) {
                const clone = response.clone();
                caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
              }
              return response;
            });
        })
    );
    return;
  }
  
  // Default: network first, cache fallback
  event.respondWith(
    fetch(request)
      .then(response => {
        if (response.ok && request.method === 'GET') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      })
      .catch(() => {
        return caches.match(request)
          .then(cached => {
            if (cached) return cached;
            
            // Return offline page for navigation requests
            if (request.mode === 'navigate') {
              return caches.match('index.html');
            }
            
            return new Response('Offline', { status: 503 });
          });
      })
  );
});

// Handle messages from the main app
self.addEventListener('message', event => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }
});

// Background sync (if supported)
self.addEventListener('sync', event => {
  console.log('[SW] Background sync:', event.tag);
});

console.log('[SW] Service Worker loaded');
