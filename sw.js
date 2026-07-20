/*
  이 앱의 서비스 워커: 앱 화면(HTML) 파일을 기기에 저장해두고,
  다음에 열 때는 Netlify에 다시 접속하지 않고 저장된 파일을 바로 보여준다.
  → 실사용자가 아무리 앱을 자주 열어도 Netlify 대역폭(크레딧)을 거의 안 쓰게 된다.

  ⚠️ 중요: 코드를 새로 배포할 때마다 아래 CACHE_VERSION 숫자를 올려야
  사용자들이 새 버전을 받아볼 수 있다. 이 숫자를 안 올리면, 이미 방문했던
  사용자들은 예전 화면이 계속 캐시에서 나온다.
  member-roster.html의 APP_VERSION과 같은 값으로 맞춰서 올리는 걸 추천.
*/
const CACHE_VERSION = '2.1.0';
const CACHE_NAME = 'pt-diary-cache-v' + CACHE_VERSION;
const PRECACHE_URLS = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => Promise.all(
        PRECACHE_URLS.map((url) =>
          fetch(url, { cache: 'reload' }).then((response) => {
            if (response.ok) return cache.put(url, response);
          })
        )
      ))
      .catch((err) => console.error('서비스 워커 캐시 저장 오류:', err))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  // Firebase, Cloudinary, cdnjs 등 다른 도메인으로 나가는 요청은 그대로 두고,
  // 이 사이트 자체(같은 origin)에서 오는 요청만 캐시 우선으로 처리한다.
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request)
        .then((response) => {
          if (response && response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => cached);
    })
  );
});
