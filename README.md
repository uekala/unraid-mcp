# Unraid MCP

MCP-Server (Model Context Protocol) für den Fernzugriff auf einen Unraid-Server – gedacht als
eigener Connector in Claude. Läuft als Docker-Container auf Unraid.

| Werkzeug | Zweck |
|---|---|
| `container_liste` | alle Container mit Zustand, Image, Ports, Neustarts |
| `container_protokoll` | Protokoll eines Containers, mit Suche und Zeitfenster |
| `container_details` | Image, Umgebungsvariablen (Geheimnisse maskiert), Pfade, Ports |
| `container_aktion` | `start`, `stop`, `restart` |
| `container_statistik` | CPU und RAM der laufenden Container |
| `system_status` | Laufzeit, Last, RAM, Docker-Übersicht, Platz |
| `ordner_inhalt` | Dateien unter `appdata` bzw. `vorlagen` |
| `datei_lesen` / `datei_schreiben` | Textdateien unter `appdata` (schreiben nur in freigegebenen Ordnern) und `vorlagen` (nur lesen) |

Keine freie Shell. Pfade beginnen mit der Wurzel: `appdata/filen-webdav/data/options.json`.

## Schutzschichten

| Schicht | Wirkung |
|---|---|
| Bearer-Token | ohne `Authorization: Bearer <MCP_TOKEN>` antwortet der Server mit 401 (offen ist nur `/gesund`) |
| Socket-Proxy | der MCP-Server sieht den Docker-Socket nicht selbst; der Proxy erlaubt nur Container ansehen, Protokolle, Statistik, starten, stoppen, neu starten – kein Anlegen, kein `kill`, kein `exec`, keine Images oder Volumes (eigene `deploy/haproxy.cfg.template`, siehe unten) |
| Schreib-Freigabe | schreiben nur in den Ordnern aus `SCHREIBEN_ERLAUBT` (Standard: `filen-webdav`) |
| Sperre | Ordner aus `GESPERRT` (Standard: `kassensturz,stichtag`) sind weder lesbar noch sichtbar |
| Zugangsdaten-Dateien | `rclone.conf`, `.env`, `*.key`, `*.pem`, `secrets*` u. Ä. sind nie lesbar oder schreibbar |
| Maskierung | Passwörter, Tokens und Schlüssel erscheinen als `***`: in `container_details`, in JSON-Dateien (nach Schlüsselnamen), in `.env`-, `.conf`- und `.yaml`-Zeilen (`SCHLUESSEL=Wert`), in Unraid-Vorlagen (`Mask="true"` oder geheimer Name) und – als JWT oder `Bearer …` – überall, auch in Protokollen. Beim Zurückschreiben von JSON bleibt der alte Wert; andere Dateien mit `***` werden nicht geschrieben |
| Kopie | vor jedem Schreiben entsteht `<datei>.<JJJJMMTT-hhmmss>.bak` |

Der Token bleibt trotzdem der Schlüssel zu allen Containern: nur in Unraid und im Connector hinterlegen, bei Verdacht
neu erzeugen.

## Einrichten auf Unraid

Mit dem Plugin **Docker Compose Manager** (Community Apps):

1. Im Unraid-Terminal:

   ```bash
   mkdir -p /mnt/user/appdata/unraid-mcp && cd /mnt/user/appdata/unraid-mcp
   wget -q https://raw.githubusercontent.com/uekala/unraid-mcp/main/deploy/docker-compose.yml
   wget -q https://raw.githubusercontent.com/uekala/unraid-mcp/main/deploy/haproxy.cfg.template
   echo "MCP_TOKEN=$(openssl rand -hex 32)" > .env && chmod 600 .env
   cat .env      # Token für den Connector notieren
   ```

2. *Docker → Compose → Add New Stack*, Name `unraid-mcp`, als Ordner `/mnt/user/appdata/unraid-mcp` wählen
   (oder im Terminal `docker compose up -d` in diesem Ordner).
3. Prüfen: `curl http://localhost:8765/gesund` → `ok` und die Version

Weitere Ordner zum Schreiben freigeben: `SCHREIBEN_ERLAUBT` in der Compose-Datei ergänzen (kommagetrennt, z. B.
`filen-webdav,ladecockpit`) und den Stack neu starten.

### Warum eine eigene Proxy-Vorlage

`tecnativa/docker-socket-proxy` prüft `POST` vor allen Freigaben: Mit `POST=0` scheitern auch `start`, `stop` und
`restart` mit 403, obwohl `ALLOW_START`, `ALLOW_STOP` und `ALLOW_RESTARTS` gesetzt sind. Mit `POST=1` wäre dagegen
zusammen mit `CONTAINERS=1` auch `containers/create` offen – damit ließe sich ein Container mit Zugriff auf den Host
anlegen. `deploy/haproxy.cfg.template` ist die Vorlage des Proxys mit genau einer geänderten Zeile: lesen wie bisher,
`POST` nur auf `/containers/<name>/start`, `/stop` und `/restart`. `kill`, `create`, `exec`, `update` und `DELETE`
bleiben gesperrt.

Ohne Compose (Container über eine Unraid-Vorlage): Datei nach `/mnt/user/appdata/unraid-mcp/haproxy.cfg.template` legen
und im Proxy-Container als Pfad einbinden – Container-Pfad `/usr/local/etc/haproxy/haproxy.cfg.template`, nur lesen.

## Von außen erreichbar machen (Tailscale Funnel)

Claude verbindet sich aus der Cloud, der Server braucht also eine öffentliche HTTPS-Adresse. Mit dem
Tailscale-Plugin auf Unraid:

```bash
tailscale funnel --bg 8765
tailscale funnel status      # zeigt https://<host>.<tailnet>.ts.net
```

Funnel muss in den Tailscale-Zugriffsregeln (`nodeAttrs`, Attribut `funnel`) für diesen Rechner erlaubt sein.

## Als Connector in Claude

*Einstellungen → Connectors → Eigenen Connector hinzufügen*

| Feld | Wert |
|---|---|
| URL | `https://<host>.<tailnet>.ts.net/mcp` |
| Request header | `Authorization` = `Bearer <Token>` |

## Umgebungsvariablen

| Variable | Bedeutung | Standard |
|---|---|---|
| `MCP_TOKEN` | Bearer-Token, mindestens 32 Zeichen | – (Pflicht) |
| `PORT` | Port im Container | `8765` |
| `DOCKER_HOST` | Adresse des Socket-Proxys | `tcp://unraid-mcp-docker:2375` (Compose) |
| `SCHREIBEN_ERLAUBT` | Ordner unter appdata, die geändert werden dürfen | `filen-webdav` |
| `GESPERRT` | Ordner unter appdata, die nicht erreichbar sind | `kassensturz,stichtag` |
| `MAX_DATEI_KB` | größte Datei zum Lesen/Schreiben | `1024` |
| `APPDATA_PFAD` / `VORLAGEN_PFAD` | Einhängepunkte im Container | `/appdata` / `/vorlagen` |
