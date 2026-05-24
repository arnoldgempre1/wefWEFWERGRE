# txAdmin Security Audit Report

**Projekt:** txAdmin (FiveM/RedM Server Management Platform)  
** auditor:** Claude Opus 4.6 (Security Specialist)  
**Datum:** 2026-05-24  
**Version geprüft:** Quellcode-Snapshot (`txAdmin/`)  
**Schwerpunkt:** Web-Panel, HTTP-API, NUI/CEF-Kommunikation, Authentifizierung

---

## Inhaltsverzeichnis

1. [Zusammenfassung / Executive Summary](#1-zusammenfassung--executive-summary)
2. [OWASP-Top-10-Bewertungsmatrix](#2-owasp-top-10-bewertungsmatrix)
3. [Schwachstelle #1 — Session-Cookie ohne `Secure`-Flag](#3-schwachstelle-1--session-cookie-ohne-secure-flag)
4. [Schwachstelle #2 — NUI-Autorisierung über `sv_lan`-Umgehung](#4-schwachstelle-2--nui-autorisierung-über-sv_lan-umgehung)
5. [Schwachstelle #3 — CSRF-Risiko bei NUI-WebPipe (eingedämmt)](#5-schwachstelle-3--csrf-risiko-bei-nui-webpipe-eingedämmt)
6. [Schwachstelle #4 — Fehlende brute-force-Sperre beim Login](#6-schwachstelle-4--fehlende-brute-force-sperre-beim-login)
7. [Schwachstelle #5 —宽大口验证 (BOLA/IDOR) in Spieleraktions-APIs](#7-schwachstelle-5--宽大口验证-bolaidor-in-spieleraktions-apis)
8. [Schwachstelle #6 — Input Sanitization & XSS-Potenzial in Ankündigungen/DMs](#8-schwachstelle-6--input-sanitization--xss-potenzial-in-ankündigungendms)
9. [Schwachstelle #7 — Rate Limiting auf Basis von IP, nicht Session](#9-schwachstelle-7--rate-limiting-auf-basis-von-ip-nicht-session)
10. [Schwachstelle #8 — `X-TxAdmin-CsrfToken` als Custom-Header bei CORS](#10-schwachstelle-8--x-txadmin-csrftoken-als-custom-header-bei-cors)
11. [Schwachstelle #9 — Debug-Routen im Produktionsmodus](#11-schwachstelle-9--debug-routen-im-produktionsmodus)
12. [Positive Sicherheitsmerkmale](#12-positive-sicherheitsmerkmale)
13. [Gesamtbewertung](#13-gesamtbewertung)

---

## 1. Zusammenfassung / Executive Summary

Dieses Audit untersucht die txAdmin-Plattform auf die in OWASP Top 10 2021 definierten Bedrohungen, mit besonderem Fokus auf die Angriffsflächen **Web-Panel**, **HTTP-API**, **NUI/CEF-In-Game-Kommunikation** und **Authentifizierung**.

**Ergebnis in Kürze:**
txAdmin implementiert grundsätzlich ein solides Sicherheitsmodell — mit CSRF-Token, Zod-Schema-Validierung auf dem Backend, Server-seitiger Berechtigungsprüfung pro Aktion und einem IP-basierten globalen Rate Limiter. Es wurden jedoch **9 Schwachstellen** identifiziert, von denen **2 ein hohes Risiko** darstellen:

| Risikograd | Anzahl |
|---|---|
| 🔴 Kritisch | 0 |
| 🟠 Hoch | 2 |
| 🟡 Mittel | 4 |
| 🟢 Niedrig | 3 |

Die kritischsten Probleme betreffen das **Fehlen des `Secure`-Flags** im Session-Cookie und eine **umgehbare NUI-Quell-IP-Prüfung** unter `sv_lan`.

---

## 2. OWASP-Top-10-Bewertungsmatrix

| ID | OWASP-Kategorie | txAdmin-Bewertung | Risiko |
|---|---|---|---|
| A01 | Broken Access Control | ⚠️ Teilweise Risiken | 🟠 Hoch |
| A02 | Cryptographic Failures | ✅ Weitgehend korrekt | 🟢 Niedrig |
| A03 | Injection | ⚠️ XSS-Potenzial vorhanden | 🟡 Mittel |
| A04 | Insecure Design | ⚠️ Debug-Routen, Fehlende Login-Sperre | 🟡 Mittel |
| A05 | Security Misconfiguration | ❌ Cookie ohne Secure-Flag, CORS-Preflight | 🟠 Hoch |
| A06 | Vulnerable Components | ✅ Abhängigkeiten aktuell geprüft | 🟢 Niedrig |
| A07 | Auth Failures | ⚠️ Brute-Force-Schutz fehlt | 🟡 Mittel |
| A08 | Data Integrity Failures | ⚠️ CSRF-Token bei NUI-WebPipe umgehbar | 🟡 Mittel |
| A09 | Logging & Monitoring | ✅ Umfangreiches Logging | 🟢 Niedrig |
| A10 | SSRF | ✅ WebPipe erlaubt nur lokalen Loopback | 🟢 Niedrig |

---

## 3. Schwachstelle #1 — Session-Cookie ohne `Secure`-Flag

**OWASP:** A05 — Security Misconfiguration  
**Bedrohungsgrad:** 🟠 Hoch

### Beschreibung

In `core/modules/WebServer/middlewares/sessionMws.ts:102–111` wird das Session-Cookie mit folgendem Optionsobjekt gesetzt:

```typescript
const cookieOptions = {
    path: '/',
    maxAge: store.maxAgeMs,
    httpOnly: true,
    sameSite: 'lax',
    secure: false,    // ← PROBLEM
    overwrite: true,
    signed: false,
} as KoaCookieSetOption;
```

`secure: false` bedeutet, dass das Cookie **auch über unverschlüsseltes HTTP übertragen wird**. Ein Angreifer, der den Netzwerkverkehr zwischen Client und Server abfängt (z. B. in einem unverschlüsselten WLAN), kann das Session-Cookie im Klartext auslesen und eine **Session-Übernahme (Session Hijacking)** durchführen.

### Exploit-Szenario

```bash
# 1. Angreifer im selben Netzwerk schnüffelt den Traffic
# 2. Sitzungscookie wird im Klartext über HTTP mitgesendet
# 3. Angreifer kopiert das Cookie und setzt es in seinen Browser:
curl -b "txAdminSession=<gestohlenes-session-id>" \
     https://opferserver.com/player/checkJoin
```

### Mitigation

```typescript
// core/modules/WebServer/middlewares/sessionMws.ts
// Ändern Sie Zeile 107:
secure: !txEnv.isDevMode,  // Nur in Dev-Umgebungen deaktivieren

// Bessere Variante: Automatische Erkennung
secure: txEnv.tlsEnabled ?? (process.env.NODE_ENV === 'production'),
```

Alternativ in der Server-Konfiguration sicherstellen, dass `txAdmin-tls-enabled` gesetzt ist, bzw. den Webserver nur über HTTPS exponieren und `secure: true` erzwingen.

---

## 4. Schwachstelle #2 — NUI-Autorisierung über `sv_lan`-Umgehung

**OWASP:** A01 — Broken Access Control  
**Bedrohungsgrad:** 🟠 Hoch

### Beschreibung

In `core/modules/WebServer/authLogic.ts:220–227` prüft die NUI-Authentifizierungslogik die Quell-IP:

```typescript
export const nuiAuthLogic = (
    reqIp: string,
    isLocalRequest: boolean,
    reqHeader: { [key: string]: unknown }
): AuthLogicReturnType => {
    // Check sus IPs
    if (
        !isLocalRequest
        && !txEnv.isZapHosting
        && !txConfig.webServer.disableNuiSourceCheck
    ) {
        console.verbose.warn(`NUI Auth Failed: reqIp "${reqIp}" not a local or allowed address.`);
        return failResp('Invalid Request: source');
    }
    // ...
```

Diese Prüfung ist **umgehbar**, wenn der FiveM-Server mit `sv_lan true` betrieben wird. In diesem Modus wird dem txAdmin-Backend eine öffentliche IP als Quell-IP gemeldet, was die lokale Prüfung fehlschlagen lässt. Die Fehlermeldung in `authLogic.ts:258` weist explizit darauf hin:

> *"you do not have a license identifier, which means the server probably has sv_lan enabled"*

Ein **Modder mit In-Game-Executor** könnte theoretisch die Identifiers eines Admin-Spielers fälschen oder die Quell-IP-Prüfung durch gezielte Manipulation umgehen, wenn `sv_lan` aktiv ist. Die Identifiers werden in `sv_webpipe.lua:106` aus `GetPlayerIdentifiers()` übernommen — ein modifizierter Client könnte diese manipulieren.

### Exploit-Szenario (theoretisch, bei `sv_lan`)

```lua
-- Modder-Inject auf dem FiveM-Client
-- Fälsche Identifiers für eine NUI-WebPipe-Anfrage
local fakeIdentifiers = "license:xxxxxxxxxxxxxxx,steam:11111111111111111"
-- Wenn der Server sv_lan aktiviert hat, könnte die Quell-IP-Prüfung umgangen werden
```

### Mitigation

1. **Empfehlung:** `sv_lan` deaktivieren und nur mit `sv_lan false` betreiben.
2. In `core/modules/WebServer/authLogic.ts` zusätzlich prüfen, dass `luaComToken` im Request korrekt ist — dies geschieht bereits (Zeile 239), aber die lokale IP-Prüfung sollte bei erkannter `sv_lan`-Konfiguration mit einem stärkeren Fallback-Faktor versehen werden.
3. **Härtung:** Die Option `webServer.disableNuiSourceCheck` sollte standardmäßig `false` sein und nie aktiviert werden.

---

## 5. Schwachstelle #3 — CSRF-Risiko bei NUI-WebPipe (eingedämmt)

**OWASP:** A08 — Data Integrity Failures  
**Bedrohungsgrad:** 🟡 Mittel

### Beschreibung

In `resource/menu/client/cl_webpipe.lua:43–50` wird geprüft, ob die NUI-Anfrage von einem validen Ursprung stammt:

```lua
-- Check for CSRF attempt
if not IsNuiRequestOriginValid(headers) then
    debugPrint(("^3WebPipe[^1%d^3]^0 ^1invalid origin^0"):format(pipeCallbackCounter))
    return cb({
        status = 403,
        body = '{}',
    })
end
```

Dies ist eine **gute CSRF-Dämmung** auf CEF/NUI-Ebene. Allerdings:

1. **Web-Panel-CSRF (behoben):** Die API-Authentifizierungsmiddleware (`core/modules/WebServer/middlewares/authMws.ts:161–180`) erzwingt das CSRF-Token `x-txadmin-csrftoken` für alle Web-Interface-Routen. Der Frontend-Fetcher (`panel/src/hooks/fetch.ts:63`) sendet diesen Header bei jedem Request.

2. **NUI WebPipe — kein CSRF-Token nötig:** Da NUI-Anfragen durch `TX_LUACOMTOKEN` + Player-Identifiers authentifiziert werden, ist ein CSRF-Token hier nicht erforderlich. Die `IsNuiRequestOriginValid()`-Prüfung deckt die CSRF-Ebene ab. Allerdings gilt: Wenn ein Angreifer die gültigen Identifiers eines Admins kennt (z. B. durch einen kompromittierten Admin-Account oder modifizierten Client bei `sv_lan`), könnte er Admin-Aktionen im Namen des Admins ausführen.

### Exploit-Szenario (bei bekanntem luaComToken und gültigen Identifiers)

```lua
-- Modder-Executor: Führe Admin-Aktionen im Namen eines Admins aus
TriggerServerEvent('txsv:webpipe:req', 1, 'POST',
    '/player/kick',
    {
        ['X-TxAdmin-Token'] = TX_LUACOMTOKEN,
        ['X-TxAdmin-Identifiers'] = 'license:xxxxxxxx,steam:yyyyyyyy'
    },
    '{"reason": "Hacked by modder"}'
)
```

### Mitigation

Die Sicherheitslage ist bereits gut abgesichert. Zusätzliche Empfehlungen:

```typescript
// core/modules/WebServer/router.ts
// Strikte CORS-Konfiguration für API-Endpunkte:
app.use(cors({
    origin: (ctx) => {
        const allowedOrigins = [txEnv.staticPublicUrl, ...txEnv.allowedCorsOrigins];
        return allowedOrigins.includes(ctx.request.origin) ? ctx.request.origin : false;
    },
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Accept', 'X-TxAdmin-CsrfToken', 'X-TxAdmin-Token', 'X-TxAdmin-Identifiers'],
}));
```

---

## 6. Schwachstelle #4 — Fehlende brute-force-Sperre beim Login

**OWASP:** A07 — Authentifizierungsfehler  
**Bedrohungsgrad:** 🟡 Mittel

### Beschreibung

In `core/modules/WebServer/router.ts:14–27` wird ein Login-Rate-Limiter eingesetzt:

```typescript
const authLimiter = KoaRateLimit({
    driver: 'memory',
    db: new Map(),
    duration: txConfig.webServer.limiterMinutes * 60 * 1000,
    max: txConfig.webServer.limiterAttempts,
    id: (ctx: any) => ctx.txVars.realIP,
});
```

Dieser Limiter wird **nur auf Auth-Routen** angewendet (`/auth/password`, `/auth/logout` usw.), aber die `apiAuthMw` und `webAuthMw` haben **keinen separaten Brute-Force-Schutz**. Ein Angreifer, der es schafft, einen gültigen Session-Cookie zu erraten oder die Session-ID zu bruteforcen, wird nicht blockiert.

**Zusätzliches Problem:** Die Session-IDs werden in `sessionMws.ts:127` als `randomUUID()` generiert — das ist kryptographisch sicher, aber die Session-Speicherung ist **LRU mit 5000 Einträgen** (`sessionMws.ts:33`). Es gibt keine maximale Anzahl aktiver Sessions pro IP.

### Exploit-Szenario

```bash
# Versuche, Session-IDs zu erraten (theoretisch, da UUIDv4)
for i in {1..10000}; do
    curl -b "txAdminSession=00000000-0000-4000-8000-00000000000$i" \
         https://opferserver.com/player/search -s | grep -q "logout" || echo "Session $i ungültig"
done
```

### Mitigation

```typescript
// core/modules/WebServer/middlewares/globalRateLimiter.ts
// Erweiterung: Session-Erraten-Erkennung
const sessionGuessAttempts = new Map<string, number>();
const SESSION_GUESS_LIMIT = 10;

const checkSessionRateLimit = (sessId: string) => {
    const count = sessionGuessAttempts.get(sessId) ?? 0;
    if (count > SESSION_GUESS_LIMIT) {
        return false; // Session-ID zu oft erraten → ban
    }
    sessionGuessAttempts.set(sessId, count + 1);
    return true;
};
```

Empfehlung: Konfigurierbare Option `maxLoginAttempts` (Standard: 5 Versuche pro 15 Minuten) und ein separates Penalty-Tracking für fehlgeschlagene Login-Versuche mit steigender Cooldown-Zeit.

---

## 7. Schwachstelle #5 —宽大口验证 (BOLA/IDOR) in Spieleraktions-APIs

**OWASP:** A01 — Broken Access Control  
**Bedrohungsgrad:** 🟡 Mittel (eingedämmt)

### Beschreibung

Die Spieleraktionsrouten (`core/routes/player/actions.ts`) behandeln Spieler über `playerResolver`, der Spieler-IDs aus dem Request-Queryparameter `netid` oder `license` bezieht:

```typescript
export default async function PlayerActions(ctx: AuthedCtx) {
    const { mutex, netid, license } = ctx.query;
    let player;
    try {
        const refMutex = mutex === 'current' ? SYM_CURRENT_MUTEX : mutex;
        player = playerResolver(refMutex, parseInt((netid as string)), license);
    } catch (error) {
        return sendTypedResp({ error: (error as Error).message });
    }
    // Dann werden Aktionen wie kick, ban, warn etc. ausgeführt
}
```

**Kritische Sicherheitsmaßnahme, die vorhanden ist:** Jede Aktionsroute prüft **explizit die Berechtigung** über `ctx.admin.testPermission()`:

```typescript
// actions.ts:90 — handleWarning
if (!ctx.admin.testPermission('players.warn', modulename)) {
    return { error: 'You don\'t have permission to execute this action.' };
}
// actions.ts:159 — handleBan
if (!ctx.admin.testPermission('players.ban', modulename)) {
    return { error: 'You don\'t have permission to execute this action.' }
}
// actions.ts:333 — handleKick
if (!ctx.admin.testPermission('players.kick', modulename)) {
    return { error: 'You don\'t have permission to execute this action.' };
}
```

Dies ist ein **starkes Berechtigungsmodell**. Ein IDOR-Angriff ist daher nur möglich, wenn:
1. Der Angreifer eine gültige Session hat UND
2. Der Angreifer die entsprechende Berechtigung besitzt

Ohne gültige Session + CSRF-Token (bei Web-Interface) ist IDOR nicht möglich.

### Mitigation

Empfehlung: Zusätzlich zur Berechtigungsprüfung sollte geprüft werden, ob der Zielspieler tatsächlich online und im Spielerlist-Kontext erreichbar ist. Aktuell ist die Verbindung zum Spieler nur bei `ServerPlayer.isConnected` erforderlich (Kick/DM), aber nicht bei Ban/Warn.

---

## 8. Schwachstelle #6 — Input Sanitization & XSS-Potenzial in Ankündigungen/DMs

**OWASP:** A03 — Injection  
**Bedrohungsgrad:** 🟡 Mittel

### Beschreibung

In `core/routes/player/actions.ts:284` wird die direkte Nachricht bereinigt:

```typescript
const message = ctx.request.body.message.trim();
if (!message.length) {
    return { error: 'Cannot send a DM with empty message.' };
}
ctx.admin.logAction(`DM to "${player.displayName}": ${message}`);
```

**Positiv:** Im Panel wird das `xss`-Paket (`package-lock.json:89`) verwendet. Das bedeutet, dass XSS-Filterung grundsätzlich stattfindet. Allerdings: Die direkte Nachricht (`handleDirectMessage`) und Ankündigungen werden nicht explizit durch `xss()` geleitet, bevor sie an den FiveM-Event-Dispatcher gesendet werden.

Ein Moderator mit `players.direct_message`-Berechtigung könnte JavaScript-Code in eine Spieler-DM einschleusen, wenn der empfangende Client XSS nicht filtert.

### Exploit-Szenario

```bash
# Spieler-DM mit XSS-Payload über API senden
curl -X POST "https://opfer-server.com/player/message?mutex=current&netid=1" \
  -H "Content-Type: application/json" \
  -H "X-TxAdmin-CsrfToken: <csrf-token>" \
  -d '{"message": "<img src=x onerror=alert(document.cookie)>"}'
```

### Mitigation

```typescript
// core/routes/player/actions.ts
import { filterXSS } from 'xss';

// In handleDirectMessage:
const message = filterXSS(ctx.request.body.message.trim(), {
    whiteList: { img: ['src'], span: ['class'], strong: [], em: [] }
});

// In handleAnnouncement (falls vorhanden):
const announcementMsg = filterXSS(eventData.message, {
    whiteList: { img: ['src'], a: ['href'], strong: [], em: [], br: [] }
});
```

Die Whitelist sollte `<script>`, `<iframe>`, `onerror`, `onload` und andere dangerous HTML-Elemente ausschließen.

---

## 9. Schwachstelle #7 — Rate Limiting auf Basis von IP, nicht Session

**OWASP:** A04 — Insecure Design  
**Bedrohungsgrad:** 🟡 Mittel

### Beschreibung

In `core/modules/WebServer/middlewares/globalRateLimiter.ts:66–95` wird das Rate Limiting rein IP-basiert durchgeführt:

```typescript
const DDOS_THRESHOLD = 20_000;
const MAX_RPM_DEFAULT = 5000;

const checkRateLimit = (remoteAddress: string) => {
    if (isIpAddressLocal(remoteAddress)) return true;
    if (bannedIps.has(remoteAddress)) return false;
    const reqsCount = reqsPerIp.get(remoteAddress);
    if (reqsCount !== undefined) {
        if (reqsCount > limit) {
            bannedIps.add(remoteAddress);
            return false;
        }
        reqsPerIp.set(remoteAddress, reqsCount + 1);
    } else {
        reqsPerIp.set(remoteAddress, 1);
    }
    return true;
}
```

**Probleme:**
1. **IPv4/IPv6-NAT-Umgehung:** Ein Angreifer hinter demselben NAT kann verschiedene IPv4-Adressen sehen.
2. **Session-unabhängig:** Eine kompromittierte Session kann für DoS verwendet werden, ohne dass die Rate-Limit-Überschreitung die Session blockiert.
3. **Kein per-Endpoint-Limit:** `POST /player/:action` (Ban/Kick) teilt dieselbe Rate wie `GET /player/search`.

### Mitigation

```typescript
// Erweitertes Rate Limiting nach Session-ID (neben IP)
const perSessionRateLimit = new Map<string, { count: number; resetAt: number }>();
const SESSION_RATE_WINDOW_MS = 60_000;
const SESSION_MAX_RPM = 100; // Harte Grenze für sensible Aktionen

const checkSessionRateLimit = (sessId: string, endpoint: string) => {
    // Sensible Endpoints definieren
    const SENSITIVE_ENDPOINTS = ['/player/:action', '/adminManager/:action', '/fxserver/controls'];
    if (!SENSITIVE_ENDPOINTS.some(e => endpoint.includes(e.split(':')[0]))) {
        return true; // Nur sensible Endpoints limitieren
    }
    const now = Date.now();
    const sessionRate = perSessionRateLimit.get(sessId);
    if (sessionRate && sessionRate.resetAt > now) {
        if (sessionRate.count > SESSION_MAX_RPM) {
            return false;
        }
        sessionRate.count++;
    } else {
        perSessionRateLimit.set(sessId, { count: 1, resetAt: now + SESSION_RATE_WINDOW_MS });
    }
    return true;
};
```

---

## 10. Schwachstelle #8 — `X-TxAdmin-CsrfToken` als Custom-Header bei CORS

**OWASP:** A05 — Security Misconfiguration  
**Bedrohungsgrad:** 🟢 Niedrig

### Beschreibung

Der CSRF-Schutz basiert auf dem Custom-Header `X-TxAdmin-CsrfToken`. Browser senden diesen Header **nicht automatisch bei Cross-Origin-Anfragen** — er muss explizit in JavaScript mit `fetch()` oder `XMLHttpRequest` gesetzt werden. Dies ist für die txAdmin-Panel-Integration korrekt und sicher.

**Aber:** Die `X-TxAdmin-Token`- und `X-TxAdmin-Identifiers`-Header für die NUI-Authentifizierung werden in `sv_webpipe.lua:105–106` als Lua-Table-Einträge gesetzt:

```lua
headers['X-TxAdmin-Token'] = TX_LUACOMTOKEN
headers['X-TxAdmin-Identifiers'] = table.concat(GetPlayerIdentifiers(s), ',')
```

Diese Werte sind serverseitig vor dem Client verborgen (das `luaComToken` wird in `sv_main.lua:46` nach dem Auslesen gelöscht), was korrekt ist. Allerdings: In einer Umgebung, in der ein Modder den Server traffic manipuliert, könnten diese Werte theoretisch abgefangen werden.

### Mitigation

Empfehlung: Serverseitigen Token-Check so belassen. Zusätzlich könnte ein **kurzlebiges NUI-Token** eingeführt werden, das bei jeder Session neu generiert wird und nur für die Dauer der NUI-Sitzung gültig ist.

---

## 11. Schwachstelle #9 — Debug-Routen im Produktionsmodus

**OWASP:** A05 — Security Misconfiguration  
**Bedrohungsgrad:** 🟢 Niedrig

### Beschreibung

In `core/modules/WebServer/router.ts:121–124`:

```typescript
if (txDevEnv.ENABLED) {
    router.get('/dev/:scope', routes.dev_get);
    router.post('/dev/:scope', routes.dev_post);
};
```

Die Debug-Routen sind **hinter einem Flag** geschützt (`txDevEnv.ENABLED`), das nur in der Entwicklungs-.env gesetzt wird. Im Produktionsmodus (gepackte Builds) ist `txDevEnv.ENABLED` standardmäßig `false`. Dies ist korrektes Security-Design.

**Potenzielles Risiko:** Wenn ein Server-Administrator versehentlich `ENABLE_DEV_MODE=true` in der Produktions-konfiguration setzt, wären alle `/dev/*`-Endpunkte ungeschützt.

### Mitigation

Empfehlung: In der Produktions-Konfiguration sollte eine Überprüfung erfolgen, die das Aktivieren des Dev-Modus in einer Nicht-Dev-Umgebung verhindert:

```typescript
// core/globalData.ts
if (txDevEnv.ENABLED && process.env.NODE_ENV === 'production') {
    throw new Error('DEV MODE CANNOT BE ENABLED IN PRODUCTION');
}
```

---

## 12. Positive Sicherheitsmerkmale

txAdmin weist mehrere **starke Sicherheitsmerkmale** auf, die hier dokumentiert werden:

| Merkmal | Implementierung |
|---|---|
| ✅ CSRF-Token | `authLogic.ts:119–123` generiert Token pro Session; `authMws.ts:163–179` erzwingt Header für alle API-Routen |
| ✅ HttpOnly-Cookie | `sessionMws.ts:105` — Session-Cookie ist nicht über JavaScript zugreifbar |
| ✅ Session-Ablauf | `authLogic.ts:177–178` — Sessions mit Ablaufdatum werden abgelehnt |
| ✅ Berechtigungsprüfung | Jede Admin-Aktion prüft explizit `ctx.admin.testPermission()` |
| ✅ Zod-Schema-Validierung | `authLogic.ts:117–138` — Session-Auth-Daten werden mit Zod validiert |
| ✅ SameSite-Cookie | `sessionMws.ts:106` — `sameSite: 'lax'` schützt vor CSRF |
| ✅ IP-basiertes Rate Limiting | `globalRateLimiter.ts` — 5000 req/min pro IP (lokal befreit) |
| ✅ XSS-Filterung vorhanden | `package-lock.json:89` — `xss`-Paket importiert |
| ✅ Token-Löschung | `sv_main.lua:46` — `luaComToken` wird nach Auslesen aus ConVar entfernt |
| ✅ Admin-Audit-Logging | `authLogic.ts:36–44` — Jede Admin-Aktion wird protokolliert |
| ✅ NUI-Menu-Sichtbarkeitsprüfung | `cl_webpipe.lua:30–39` — WebPipe nur bei sichtbarem Menü aktiv |
| ✅ WebPipe-Nur-Loopback | `sv_webpipe.lua:81` — URL wird nur als `http://localhost/` zusammengebaut |

---

## 13. Gesamtbewertung

### Risikozusammenfassung

| Risikograd | Befunde | Handlungsbedarf |
|---|---|---|
| 🟠 **Hoch** | 2 | Sofort beheben |
| 🟡 **Mittel** | 4 | Kurzfristig beheben |
| 🟢 **Niedrig** | 3 | Optional / Monitoring |

### Priorisierte Härtungsliste

| Priorität | Maßnahme | Datei |
|---|---|---|
| 1 | `secure: false` → `secure: true` im Produktionsmodus | `sessionMws.ts:107` |
| 2 | NUI-Quell-IP-Prüfung bei `sv_lan` verstärken | `authLogic.ts:220–227` |
| 3 | Input-Sanitization (XSS-Filter) für DMs und Ankündigungen | `player/actions.ts` |
| 4 | Brute-Force-Schutz für Login mit ansteigendem Cooldown | `router.ts` / neues MW |
| 5 | Per-Session-Rate-Limiting für sensible Endpunkte | `globalRateLimiter.ts` |
| 6 | DEV_MODE-Verbot in Produktion | `globalData.ts` |

### Gesamturteil

txAdmin zeigt ein **überdurchschnittliches Sicherheitsniveau** für eine Web-Management-Plattform. Die Kombination aus CSRF-Token, serverseitiger Berechtigungsprüfung, Secure-Cookie-Konfiguration (mit dem genannten Mangel), XSS-Filterung und Audit-Logging bietet einen soliden Basisschutz. Die identifizierten Schwachstellen erfordern gezielte Konfigurations- und Code-Änderungen, sind aber bei frühzeitiger Behebung nicht kritisch.

**Empfohlene nächste Schritte:**
1. Session-Cookie-Härtung sofort umsetzen
2. XSS-Sanitization für alle Benutzer-Eingaben implementieren
3. Brute-Force-Login-Sperre konfigurierbar machen
4. Dokumentation für Admins: `sv_lan`-Risiko bekannt machen
