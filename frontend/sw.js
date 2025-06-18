/**
 * OneID 2.0 Service Worker
 * Handles caching, offline functionality, and push notifications
 */

const CACHE_NAME = 'oneid-v2.0.0';
const STATIC_CACHE = 'oneid-static-v2.0.0';
const DYNAMIC_CACHE = 'oneid-dynamic-v2.0.0';

// Files to cache for offline use
const STATIC_FILES = [
    '/',
    '/index.html',
    '/css/styles.css',
    '/js/app.js',
    '/js/auth.js',
    '/js/api.js',
    '/js/utils.js',
    '/js/totp.js',
    '/manifest.json',
    '/assets/icons/icon-192x192.png',
    '/assets/icons/icon-512x512.png',
    'https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@300;400;500;600;700&display=swap',
    'https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js'
];

// API endpoints that should be cached
const CACHEABLE_APIS = [
    '/api/v1/auth/profile',
    '/api/v1/security/score',
    '/api/v1/devices'
];

// === INSTALLATION ===
self.addEventListener('install', (event) => {
    console.log('🔧 Service Worker: Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('📦 Service Worker: Caching static files...');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('✅ Service Worker: Installation complete');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('❌ Service Worker: Installation failed:', error);
            })
    );
});

// === ACTIVATION ===
self.addEventListener('activate', (event) => {
    console.log('🚀 Service Worker: Activating...');
    
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('🗑️ Service Worker: Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('✅ Service Worker: Activation complete');
                return self.clients.claim();
            })
    );
});

// === FETCH HANDLING ===
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Handle different types of requests
    if (request.method === 'GET') {
        if (isStaticFile(request.url)) {
            event.respondWith(handleStaticFile(request));
        } else if (isAPIRequest(request.url)) {
            event.respondWith(handleAPIRequest(request));
        } else if (isExternalResource(request.url)) {
            event.respondWith(handleExternalResource(request));
        } else {
            event.respondWith(handleGenericRequest(request));
        }
    } else {
        // POST, PUT, DELETE requests - always go to network
        event.respondWith(handleMutatingRequest(request));
    }
});

// === STATIC FILE HANDLING ===
function isStaticFile(url) {
    return STATIC_FILES.some(file => url.includes(file.replace('/', ''))) ||
           url.includes('/css/') ||
           url.includes('/js/') ||
           url.includes('/assets/');
}

async function handleStaticFile(request) {
    try {
        // Try cache first
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // If not in cache, fetch and cache
        const networkResponse = await fetch(request);
        if (networkResponse.ok) {
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
        
    } catch (error) {
        console.error('❌ Service Worker: Static file error:', error);
        
        // Return offline fallback
        if (request.url.includes('.html') || request.url.endsWith('/')) {
            return caches.match('/index.html');
        }
        
        // Return generic offline response
        return new Response('Offline', {
            status: 503,
            statusText: 'Service Unavailable'
        });
    }
}

// === API REQUEST HANDLING ===
function isAPIRequest(url) {
    return url.includes('/api/');
}

async function handleAPIRequest(request) {
    try {
        // Try network first for API requests
        const networkResponse = await fetch(request);
        
        // Cache successful GET responses for certain endpoints
        if (networkResponse.ok && request.method === 'GET' && isCacheableAPI(request.url)) {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
        
    } catch (error) {
        console.error('❌ Service Worker: API request failed:', error);
        
        // Try to return cached version for GET requests
        if (request.method === 'GET') {
            const cachedResponse = await caches.match(request);
            if (cachedResponse) {
                console.log('📦 Service Worker: Returning cached API response');
                return cachedResponse;
            }
        }
        
        // Return offline API response
        return new Response(JSON.stringify({
            error: 'offline',
            message: 'Request failed - you appear to be offline'
        }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

function isCacheableAPI(url) {
    return CACHEABLE_APIS.some(api => url.includes(api));
}

// === EXTERNAL RESOURCE HANDLING ===
function isExternalResource(url) {
    return url.includes('googleapis.com') ||
           url.includes('jsdelivr.net') ||
           url.includes('cdnjs.com');
}

async function handleExternalResource(request) {
    try {
        // Try cache first for external resources
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Fetch with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        const networkResponse = await fetch(request, {
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (networkResponse.ok) {
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
        
    } catch (error) {
        console.error('❌ Service Worker: External resource failed:', error);
        
        // Try cached version
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Return empty response for scripts/styles
        if (request.url.includes('.js')) {
            return new Response('console.warn("Script loaded from cache failed");', {
                headers: { 'Content-Type': 'application/javascript' }
            });
        } else if (request.url.includes('.css')) {
            return new Response('/* Stylesheet loaded from cache failed */', {
                headers: { 'Content-Type': 'text/css' }
            });
        }
        
        return new Response('', { status: 204 });
    }
}

// === MUTATING REQUEST HANDLING ===
async function handleMutatingRequest(request) {
    try {
        return await fetch(request);
    } catch (error) {
        console.error('❌ Service Worker: Mutating request failed:', error);
        
        // Store failed requests for later retry
        await storeFailedRequest(request);
        
        return new Response(JSON.stringify({
            error: 'offline',
            message: 'Request queued for retry when online',
            queued: true
        }), {
            status: 202,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// === GENERIC REQUEST HANDLING ===
async function handleGenericRequest(request) {
    try {
        return await fetch(request);
    } catch (error) {
        const cachedResponse = await caches.match(request);
        return cachedResponse || new Response('Offline', { status: 503 });
    }
}

// === BACKGROUND SYNC ===
self.addEventListener('sync', (event) => {
    console.log('🔄 Service Worker: Background sync triggered:', event.tag);
    
    if (event.tag === 'retry-failed-requests') {
        event.waitUntil(retryFailedRequests());
    }
});

async function storeFailedRequest(request) {
    try {
        const requestData = {
            url: request.url,
            method: request.method,
            headers: Object.fromEntries(request.headers.entries()),
            body: await request.text(),
            timestamp: Date.now()
        };
        
        // Store in IndexedDB for persistence
        const db = await openDB();
        const tx = db.transaction(['failed_requests'], 'readwrite');
        const store = tx.objectStore('failed_requests');
        await store.add(requestData);
        
        // Register for background sync
        await self.registration.sync.register('retry-failed-requests');
        
    } catch (error) {
        console.error('❌ Service Worker: Failed to store request:', error);
    }
}

async function retryFailedRequests() {
    try {
        const db = await openDB();
        const tx = db.transaction(['failed_requests'], 'readwrite');
        const store = tx.objectStore('failed_requests');
        const requests = await store.getAll();
        
        for (const requestData of requests) {
            try {
                const response = await fetch(requestData.url, {
                    method: requestData.method,
                    headers: requestData.headers,
                    body: requestData.body || undefined
                });
                
                if (response.ok) {
                    await store.delete(requestData.id);
                    console.log('✅ Service Worker: Retried request successfully:', requestData.url);
                }
                
            } catch (error) {
                console.log('⏭️ Service Worker: Request still failing, will retry later:', requestData.url);
            }
        }
        
    } catch (error) {
        console.error('❌ Service Worker: Failed to retry requests:', error);
    }
}

// === INDEXEDDB HELPERS ===
async function openDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('OneIDCache', 1);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            
            if (!db.objectStoreNames.contains('failed_requests')) {
                const store = db.createObjectStore('failed_requests', {
                    keyPath: 'id',
                    autoIncrement: true
                });
                store.createIndex('timestamp', 'timestamp');
            }
        };
    });
}

// === PUSH NOTIFICATIONS ===
self.addEventListener('push', (event) => {
    console.log('📢 Service Worker: Push notification received');
    
    let notificationData = {
        title: 'OneID Security Alert',
        body: 'Security notification from OneID',
        icon: '/assets/icons/icon-192x192.png',
        badge: '/assets/icons/badge-72x72.png',
        tag: 'oneid-security',
        requireInteraction: true,
        actions: [
            {
                action: 'view',
                title: 'View Details',
                icon: '/assets/icons/action-view.png'
            },
            {
                action: 'dismiss',
                title: 'Dismiss',
                icon: '/assets/icons/action-dismiss.png'
            }
        ]
    };
    
    if (event.data) {
        try {
            const data = event.data.json();
            notificationData = { ...notificationData, ...data };
        } catch (error) {
            console.error('❌ Service Worker: Failed to parse push data:', error);
        }
    }
    
    event.waitUntil(
        self.registration.showNotification(notificationData.title, notificationData)
    );
});

// === NOTIFICATION CLICK HANDLING ===
self.addEventListener('notificationclick', (event) => {
    console.log('👆 Service Worker: Notification clicked:', event.action);
    
    event.notification.close();
    
    if (event.action === 'view') {
        event.waitUntil(
            clients.openWindow('/?notification=security')
        );
    }
    // 'dismiss' or no action - just close
});

// === MESSAGE HANDLING ===
self.addEventListener('message', (event) => {
    console.log('💬 Service Worker: Message received:', event.data);
    
    if (event.data && event.data.type) {
        switch (event.data.type) {
            case 'SKIP_WAITING':
                self.skipWaiting();
                break;
                
            case 'GET_VERSION':
                event.ports[0].postMessage({ version: CACHE_NAME });
                break;
                
            case 'CLEAR_CACHE':
                clearAllCaches().then(() => {
                    event.ports[0].postMessage({ success: true });
                });
                break;
                
            case 'CACHE_STATS':
                getCacheStats().then(stats => {
                    event.ports[0].postMessage(stats);
                });
                break;
        }
    }
});

// === UTILITY FUNCTIONS ===
async function clearAllCaches() {
    const cacheNames = await caches.keys();
    return Promise.all(
        cacheNames.map(cacheName => caches.delete(cacheName))
    );
}

async function getCacheStats() {
    const cacheNames = await caches.keys();
    const stats = {};
    
    for (const cacheName of cacheNames) {
        const cache = await caches.open(cacheName);
        const keys = await cache.keys();
        stats[cacheName] = keys.length;
    }
    
    return stats;
}

// === ERROR HANDLING ===
self.addEventListener('error', (event) => {
    console.error('❌ Service Worker: Global error:', event.error);
});

self.addEventListener('unhandledrejection', (event) => {
    console.error('❌ Service Worker: Unhandled rejection:', event.reason);
});

console.log('🛡️ OneID 2.0 Service Worker loaded successfully');
