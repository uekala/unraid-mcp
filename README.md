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
| `datei_lesen` / `datei_schreiben` | Textdateien unter `appdata` (schreiben) und `vorlagen` (nur lesen) |

Keine freie Shell. Pfade beginnen mit der Wurzel: `appdata/filen-webdav/data/options.json`.

**Geheimnisse:** In `container_details` und beim Lesen von JSON-Dateien erscheinen Werte, deren Schlüssel nach
Passwort, Token, Key oder Secret klingt, als `***`. Wird eine JSON-Datei mit `***` zurückgeschrieben, bleibt der
alte Wert erhalten. Vor jedem Schreiben entsteht eine Kopie `<datei>.<JJJJMMTT-hhmmss>.bak`.

> Der Container bekommt den Docker-Socket und damit volle Kontrolle über Docker auf dem Host. Den Token wie ein
> Root-Passwort behandeln.

## Einrichten auf Unraid

1. Token erzeugen (Unraid-Terminal): `openssl rand -hex 32`
2. Container anlegen – entweder die Vorlage `unraid/unraid-mcp.xml` nach
   `/boot/config/plugins/dockerMan/templates-user/my-unraid-mcp.xml` kopieren und unter *Docker → Add Container*
   auswählen, oder von Hand:

   | Feld | Wert |
   |---|---|
   | Repository | `ghcr.io/uekala/unraid-mcp:latest` |
   | Port | `8765` → `8765` |
   | Variable `MCP_TOKEN` | Token aus Schritt 1 |
   | Pfad | `/var/run/docker.sock` → `/var/run/docker.sock` |
   | Pfad | `/mnt/user/appdata` → `/appdata` (lesen/schreiben) |
   | Pfad | `/boot/config/plugins/dockerMan/templates-user` → `/vorlagen` (nur lesen) |

3. Prüfen: `curl http://<Unraid-IP>:8765/gesund` → `ok 0.1.0`

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
| `MAX_DATEI_KB` | größte Datei zum Lesen/Schreiben | `1024` |
| `APPDATA_PFAD` / `VORLAGEN_PFAD` | Einhängepunkte im Container | `/appdata` / `/vorlagen` |
