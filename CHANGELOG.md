# Änderungen

## 0.2.1

- Geheimnisse werden jetzt auch außerhalb von JSON maskiert: in `.env`-, `.conf`- und `.yaml`-Zeilen (z. B.
  `ladecockpit.env`), in Unraid-Vorlagen (Werte mit `Mask="true"` oder geheimem Namen) sowie Tokens (JWT, `Bearer …`)
  in allen Dateien, Protokollen und Container-Einstellungen. Vorher waren diese Werte über `datei_lesen` lesbar.

## 0.2.0

- Docker nur noch über einen vorgeschalteten Socket-Proxy (`deploy/docker-compose.yml`): ansehen, Protokolle,
  Statistik, starten, stoppen, neu starten – kein Anlegen, kein `exec`.
- Schreiben nur in den Ordnern aus `SCHREIBEN_ERLAUBT` (Standard `filen-webdav`).
- `GESPERRT` (Standard `kassensturz,stichtag`): Ordner weder lesbar noch sichtbar.
- Dateien mit Zugangsdaten (`rclone.conf`, `.env`, Schlüssel) sind gesperrt.
- `ordner_inhalt` zeigt Pfade relativ statt eingerückt.

## 0.1.0

- Erste Fassung: Container, Protokolle, Appdata per MCP, Bearer-Token.
