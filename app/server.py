"""Unraid MCP – Fernzugriff auf Container, Protokolle und Appdata eines Unraid-Servers über das Model Context Protocol.

Zugriff nur mit Bearer-Token (MCP_TOKEN). Keine freie Shell: Container steuern, Protokolle lesen,
Dateien unter den freigegebenen Wurzeln lesen und schreiben.
"""

import datetime as dt
import functools
import hmac
import json
import os
import re
import shutil
import tempfile
import time

import docker
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

VERSION = open(os.path.join(os.path.dirname(__file__), "VERSION")).read().strip()
TOKEN = os.environ.get("MCP_TOKEN", "")
PORT = int(os.environ.get("PORT", "8765"))
MAX_LESEN = int(os.environ.get("MAX_DATEI_KB", "1024")) * 1024
MAX_AUSGABE = 60_000

# Freigegebene Wurzeln: Name -> (Pfad im Container, schreibbar)
WURZELN = {
    "appdata": (os.environ.get("APPDATA_PFAD", "/appdata"), True),
    "vorlagen": (os.environ.get("VORLAGEN_PFAD", "/vorlagen"), False),
}
def _liste(name, standard):
    return {x.strip().strip("/") for x in os.environ.get(name, standard).split(",") if x.strip()}


# Ordner direkt unter appdata: SCHREIBEN = nur diese dürfen geändert werden, GESPERRT = weder lesen noch schreiben
SCHREIBEN = _liste("SCHREIBEN_ERLAUBT", "filen-webdav")
GESPERRT = _liste("GESPERRT", "kassensturz,stichtag")
# Dateien mit Zugangsdaten, die nie gelesen oder geschrieben werden (auch nicht maskiert)
GEHEIME_DATEI = re.compile(r"(^\.env$|^rclone\.conf$|\.(key|pem|p12|pfx|kdbx)$|^secrets?\b|^id_(rsa|ed25519))", re.IGNORECASE)
# Container, die dieser Server nie stoppt
GESCHUETZT = _liste("GESCHUETZT", "unraid-mcp,unraid-mcp-docker")
GEHEIM = re.compile(r"(pass|token|secret|key|pwd|credential)", re.IGNORECASE)
MASKE = "***"
# Werte, die unabhängig vom Dateityp nie im Klartext erscheinen: JWTs (z. B. HA-Tokens) und Bearer/Basic-Angaben
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_AUTH = re.compile(r"(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
# Zeilen der Form SCHLUESSEL=Wert oder schluessel: Wert (.env, .conf, .ini, .yaml)
_ZUWEISUNG = re.compile(r"^(\s*(?:#\s*)?(?:export\s+)?[\"']?([\w.-]+)[\"']?\s*[=:]\s*)(\S.*?)\s*$")
# Unraid-Vorlagen: <Config Name=".." Target=".." Mask="true">Wert</Config> und Elemente mit geheimem Namen
_XML_CONFIG = re.compile(r"(<Config\b([^>]*)>)([^<]+)(</Config>)", re.IGNORECASE)
_XML_ELEMENT = re.compile(r"(<([\w.-]+)>)([^<]+)(</\2>)")

_docker = None


class Fehler(ToolError):
    """Erwarteter Fehler – der Text erreicht den Aufrufer."""


def dk():
    global _docker
    if _docker is None:
        _docker = docker.from_env()
    return _docker


def kuerzen(text, grenze=MAX_AUSGABE):
    if len(text) <= grenze:
        return text
    return f"… ({len(text) - grenze} Zeichen am Anfang weggelassen)\n" + text[-grenze:]


def container(name):
    try:
        return dk().containers.get(name)
    except docker.errors.NotFound:
        namen = sorted(c.name for c in dk().containers.list(all=True))
        raise Fehler(f"Container „{name}“ gibt es nicht. Vorhanden: {', '.join(namen)}")


def maskiere_env(env):
    aus = {}
    for zeile in env or []:
        k, _, v = zeile.partition("=")
        aus[k] = MASKE if (v and GEHEIM.search(k)) else v
    return aus


def maskiere_json(obj):
    if isinstance(obj, dict):
        return {k: (MASKE if (isinstance(v, str) and v and GEHEIM.search(k)) else maskiere_json(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [maskiere_json(v) for v in obj]
    return obj


def _attribut(attrs, name):
    m = re.search(rf'\b{name}="([^"]*)"', attrs, re.IGNORECASE)
    return m.group(1) if m else ""


def maskiere_text(text, art="text"):
    """Geheimnisse in Text maskieren. art: "xml" (Unraid-Vorlagen), "text" (env/conf/ini/yaml) oder "frei"
    (nur JWTs und Bearer/Basic, z. B. für Protokolle und bereits maskiertes JSON)."""
    if art == "xml":
        def config(m):
            attrs = m.group(2)
            geheim = (_attribut(attrs, "Mask").lower() == "true" or GEHEIM.search(_attribut(attrs, "Name"))
                      or GEHEIM.search(_attribut(attrs, "Target")))
            return m.group(1) + (MASKE if geheim and m.group(3).strip() else m.group(3)) + m.group(4)
        text = _XML_CONFIG.sub(config, text)
        text = _XML_ELEMENT.sub(
            lambda m: m.group(1) + (MASKE if GEHEIM.search(m.group(2)) and m.group(3).strip() else m.group(3)) + m.group(4),
            text)
    elif art == "text":
        zeilen = []
        for z in text.split("\n"):
            m = _ZUWEISUNG.match(z)
            if m and GEHEIM.search(m.group(2)):
                z = m.group(1) + MASKE
            zeilen.append(z)
        text = "\n".join(zeilen)
    text = _JWT.sub(MASKE, text)
    return _AUTH.sub(lambda m: m.group(1) + MASKE, text)


def masken_zurueck(neu, alt):
    """Werte "***" in neuen JSON-Daten durch die alten Geheimnisse ersetzen."""
    if isinstance(neu, dict) and isinstance(alt, dict):
        return {k: (alt.get(k) if (v == MASKE and GEHEIM.search(k) and k in alt) else masken_zurueck(v, alt.get(k)))
                for k, v in neu.items()}
    if isinstance(neu, list) and isinstance(alt, list):
        return [masken_zurueck(v, alt[i] if i < len(alt) else None) for i, v in enumerate(neu)]
    return neu


def aufloesen(pfad, schreiben=False):
    """'appdata/filen-webdav/data/options.json' -> echter Pfad, nur innerhalb der Wurzel."""
    teile = pfad.strip().strip("/").split("/", 1)
    if teile[0] not in WURZELN:
        raise Fehler(f"Pfad muss mit einer Wurzel beginnen: {', '.join(WURZELN)} (z. B. appdata/filen-webdav)")
    basis, schreibbar = WURZELN[teile[0]]
    if schreiben and not schreibbar:
        raise Fehler(f"„{teile[0]}“ ist nur lesbar")
    if not os.path.isdir(basis):
        raise Fehler(f"„{teile[0]}“ ist im Container nicht eingebunden ({basis})")
    basis = os.path.realpath(basis)
    ziel = os.path.realpath(os.path.join(basis, teile[1] if len(teile) > 1 else ""))
    if ziel != basis and not ziel.startswith(basis + os.sep):
        raise Fehler("Pfad liegt außerhalb der Freigabe")
    if teile[0] == "appdata":
        rel = os.path.relpath(ziel, basis)
        oben = "" if rel == "." else rel.split(os.sep)[0]
        if oben in GESPERRT:
            raise Fehler(f"„appdata/{oben}“ ist gesperrt")
        if schreiben and oben not in SCHREIBEN:
            erlaubt = ", ".join(sorted(SCHREIBEN)) or "keine"
            raise Fehler(f"Schreiben nur unter appdata/{{{erlaubt}}} erlaubt")
    if GEHEIME_DATEI.search(os.path.basename(ziel)):
        raise Fehler("Datei enthält Zugangsdaten und ist gesperrt")
    return ziel


mcp = MCPServer(
    name="unraid",
    title="Unraid",
    version=VERSION,
    instructions=(
        "Zugriff auf den Unraid-Server: Docker-Container auflisten, Protokolle lesen, starten/stoppen/neu starten, "
        "Einstellungen ansehen und Dateien unter appdata lesen; ändern nur in den freigegebenen Ordnern, gesperrte Ordner und "
        "Dateien mit Zugangsdaten (rclone.conf, .env, Schlüssel) sind nicht erreichbar (vorlagen = Unraid-Vorlagen, nur lesen). "
        "Geheimnisse (Passwörter, Tokens, Schlüssel) erscheinen als *** – in JSON, in .env/.conf-Zeilen, in Vorlagen und in "
        "Protokollen; beim Schreiben einer JSON-Datei bleibt ein *** der alte Wert, andere Dateien mit *** werden nicht "
        "geschrieben. Vor dem Schreiben wird eine .bak-Kopie angelegt. Nach Änderungen an Einstellungen den Container "
        "neu starten."
    ),
)


def werkzeug(fn):
    """Als MCP-Werkzeug anmelden; Docker- und Dateifehler mit ihrem Text zurückgeben."""
    @functools.wraps(fn)
    def huelle(*a, **k):
        try:
            return fn(*a, **k)
        except ToolError:
            raise
        except (docker.errors.DockerException, OSError) as e:
            raise Fehler(str(e)) from e
    return mcp.tool()(huelle)


@werkzeug
def container_liste(nur_laufende: bool = False) -> str:
    """Alle Docker-Container mit Zustand, Image, Ports und Startzeit."""
    zeilen = []
    for c in sorted(dk().containers.list(all=not nur_laufende), key=lambda c: c.name):
        a = c.attrs
        ports = []
        for innen, aussen in (a.get("NetworkSettings", {}).get("Ports") or {}).items():
            for p in aussen or []:
                ports.append(f"{p.get('HostPort')}->{innen}")
        st = a.get("State", {})
        gesund = (st.get("Health") or {}).get("Status")
        zeilen.append(
            f"{c.name} | {st.get('Status')}{' (' + gesund + ')' if gesund else ''} | "
            f"{a.get('Config', {}).get('Image')} | seit {st.get('StartedAt', '')[:19]} | "
            f"Neustarts {a.get('RestartCount', 0)} | {', '.join(ports) or '-'}"
        )
    return "Name | Zustand | Image | gestartet | Neustarts | Ports\n" + "\n".join(zeilen)


@werkzeug
def container_protokoll(name: str, zeilen: int = 200, suche: str = "", seit_minuten: int = 0) -> str:
    """Protokoll (stdout/stderr) eines Containers. suche filtert Zeilen (Groß/klein egal);
    mit suche werden bis zu 20.000 Zeilen durchsucht und die letzten `zeilen` Treffer gezeigt."""
    c = container(name)
    kw = {"timestamps": True, "tail": 20000 if suche else max(1, min(zeilen, 5000))}
    if seit_minuten > 0:
        kw["since"] = int(time.time() - seit_minuten * 60)
    text = c.logs(**kw).decode("utf-8", "replace")
    liste = text.splitlines()
    if suche:
        s = suche.lower()
        liste = [z for z in liste if s in z.lower()][-max(1, zeilen):]
    return kuerzen(maskiere_text("\n".join(liste), "frei")) or "(keine Zeilen)"


@werkzeug
def container_details(name: str) -> str:
    """Einstellungen eines Containers: Image, Umgebungsvariablen (Geheimnisse maskiert), Pfade, Ports, Netzwerk."""
    c = container(name)
    a = c.attrs
    hc = a.get("HostConfig", {})
    daten = {
        "name": c.name,
        "image": a.get("Config", {}).get("Image"),
        "image_id": a.get("Image", "")[:19],
        "zustand": a.get("State", {}),
        "neustart_regel": hc.get("RestartPolicy"),
        "netzwerk": hc.get("NetworkMode"),
        "ports": hc.get("PortBindings"),
        "pfade": [f"{m.get('Source')} -> {m.get('Destination')} ({'rw' if m.get('RW') else 'ro'})" for m in a.get("Mounts", [])],
        "umgebung": maskiere_env(a.get("Config", {}).get("Env")),
        "labels": {k: v for k, v in (a.get("Config", {}).get("Labels") or {}).items() if k.startswith(("net.unraid", "org.opencontainers.image.version"))},
        "speicher_grenze": hc.get("Memory"),
    }
    return kuerzen(maskiere_text(json.dumps(daten, indent=1, ensure_ascii=False, default=str), "frei"))


@werkzeug
def container_aktion(name: str, aktion: str) -> str:
    """Container steuern: aktion = start, stop oder restart."""
    if aktion not in ("start", "stop", "restart"):
        raise Fehler("aktion muss start, stop oder restart sein")
    if name in GESCHUETZT and aktion == "stop":
        raise Fehler(f"„{name}“ gehört zu diesem MCP-Server und wird nicht gestoppt")
    c = container(name)
    getattr(c, aktion)(timeout=30) if aktion != "start" else c.start()
    c.reload()
    return f"{c.name}: {aktion} ausgeführt, Zustand jetzt {c.status}"


@werkzeug
def container_statistik(name: str = "") -> str:
    """CPU- und Speicherverbrauch der laufenden Container (oder eines einzelnen)."""
    ziele = [container(name)] if name else dk().containers.list()
    zeilen = []
    for c in sorted(ziele, key=lambda c: c.name):
        s = c.stats(stream=False)
        cpu = s.get("cpu_stats", {})
        vor = s.get("precpu_stats", {})
        delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - vor.get("cpu_usage", {}).get("total_usage", 0)
        sys_delta = cpu.get("system_cpu_usage", 0) - vor.get("system_cpu_usage", 0)
        kerne = cpu.get("online_cpus") or 1
        prozent = (delta / sys_delta * kerne * 100) if sys_delta > 0 else 0
        mem = s.get("memory_stats", {})
        zeilen.append(f"{c.name} | CPU {prozent:.1f} % | RAM {mem.get('usage', 0) / 2**20:.0f} MiB"
                      f" von {mem.get('limit', 0) / 2**30:.1f} GiB")
    return "\n".join(zeilen) or "(keine laufenden Container)"


@werkzeug
def system_status() -> str:
    """Laufzeit, Last, Arbeitsspeicher, Docker-Übersicht und Platz der Freigaben."""
    aus = []
    try:
        sek = float(open("/proc/uptime").read().split()[0])
        aus.append(f"Laufzeit: {dt.timedelta(seconds=int(sek))}")
        aus.append("Last (1/5/15 min): " + " ".join(open("/proc/loadavg").read().split()[:3]))
        mem = {z.split(":")[0]: int(z.split()[1]) for z in open("/proc/meminfo") if z.split(":")[0] in ("MemTotal", "MemAvailable")}
        aus.append(f"RAM: {(mem['MemTotal'] - mem['MemAvailable']) / 2**20:.1f} von {mem['MemTotal'] / 2**20:.1f} GiB belegt")
    except Exception as e:
        aus.append(f"/proc nicht lesbar: {e}")
    info = dk().info()
    aus.append(f"Docker {info.get('ServerVersion')}: {info.get('ContainersRunning')} laufen, "
               f"{info.get('ContainersStopped')} gestoppt, {info.get('Images')} Images, Host {info.get('Name')}, "
               f"{info.get('OperatingSystem')}, Kernel {info.get('KernelVersion')}, {info.get('NCPU')} Kerne")
    for wurzel, (pfad, _) in WURZELN.items():
        if os.path.isdir(pfad):
            du = shutil.disk_usage(pfad)
            aus.append(f"{wurzel}: {du.used / 2**30:.1f} von {du.total / 2**30:.1f} GiB belegt, {du.free / 2**30:.1f} GiB frei")
    return "\n".join(aus)


@werkzeug
def ordner_inhalt(pfad: str = "appdata", tiefe: int = 1) -> str:
    """Dateien und Ordner unter einer Freigabe, z. B. 'appdata' oder 'appdata/filen-webdav'. tiefe 1–4."""
    basis = aufloesen(pfad)
    if not os.path.isdir(basis):
        raise Fehler("Kein Ordner")
    tiefe = max(1, min(tiefe, 4))
    zeilen = []
    start = basis.rstrip(os.sep).count(os.sep)
    for wurzel, ordner, dateien in os.walk(basis):
        ebene = wurzel.count(os.sep) - start
        if ebene >= tiefe:
            ordner[:] = []
            continue
        if ebene == 0 and os.path.realpath(wurzel) == os.path.realpath(WURZELN["appdata"][0]):
            ordner[:] = [o for o in ordner if o not in GESPERRT]
        ordner.sort()
        rel = os.path.relpath(wurzel, basis)
        vor = "" if rel == "." else rel + "/"
        for o in ordner:
            zeilen.append(f"{vor}{o}/")
        for d in sorted(dateien):
            try:
                st = os.stat(os.path.join(wurzel, d))
                zeilen.append(f"{vor}{d}  {st.st_size} B  {dt.datetime.fromtimestamp(st.st_mtime):%Y-%m-%d %H:%M}")
            except OSError:
                zeilen.append(f"{vor}{d}  (nicht lesbar)")
        if len(zeilen) > 2000:
            zeilen.append("… (gekürzt)")
            break
    return kuerzen("\n".join(zeilen)) or "(leer)"


@werkzeug
def datei_lesen(pfad: str) -> str:
    """Textdatei lesen, z. B. 'appdata/filen-webdav/data/options.json'. Geheimnisse erscheinen als ***: in JSON nach
    Schlüsselnamen, in .env/.conf/.yaml-Zeilen (SCHLUESSEL=Wert), in Unraid-Vorlagen (Mask="true") sowie Tokens überall."""
    ziel = aufloesen(pfad)
    if not os.path.isfile(ziel):
        raise Fehler("Keine Datei")
    if os.path.getsize(ziel) > MAX_LESEN:
        raise Fehler(f"Datei größer als {MAX_LESEN // 1024} KB")
    text = open(ziel, "rb").read().decode("utf-8", "replace")
    if ziel.lower().endswith(".json"):
        try:
            return maskiere_text(json.dumps(maskiere_json(json.loads(text)), indent=2, ensure_ascii=False), "frei")
        except ValueError:
            pass
    return maskiere_text(text, "xml" if ziel.lower().endswith(".xml") else "text")


@werkzeug
def datei_schreiben(pfad: str, inhalt: str) -> str:
    """Textdatei in einem freigegebenen Ordner unter appdata schreiben (neu oder ersetzen). Vorher entsteht eine Kopie <datei>.<zeit>.bak.
    In JSON-Dateien wird *** durch den bisherigen geheimen Wert ersetzt. Ungültiges JSON wird abgelehnt."""
    ziel = aufloesen(pfad, schreiben=True)
    if os.path.isdir(ziel):
        raise Fehler("Pfad ist ein Ordner")
    if len(inhalt.encode()) > MAX_LESEN:
        raise Fehler(f"Inhalt größer als {MAX_LESEN // 1024} KB")
    vorhanden = os.path.isfile(ziel)
    if ziel.endswith(".json"):
        try:
            neu = json.loads(inhalt)
        except ValueError as e:
            raise Fehler(f"Ungültiges JSON: {e}")
        if vorhanden:
            try:
                neu = masken_zurueck(neu, json.load(open(ziel)))
            except ValueError:
                pass
        inhalt = json.dumps(neu, indent=2, ensure_ascii=False) + "\n"
    elif MASKE in inhalt and vorhanden:
        raise Fehler("Inhalt enthält *** – nur in JSON-Dateien werden maskierte Werte übernommen")
    os.makedirs(os.path.dirname(ziel), exist_ok=True)
    sicherung = ""
    if vorhanden:
        sicherung = f"{ziel}.{dt.datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(ziel, sicherung)
        st = os.stat(ziel)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(ziel), prefix=".unraid-mcp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(inhalt)
    if vorhanden:
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
    else:
        os.chmod(tmp, 0o644)
    os.replace(tmp, ziel)
    return f"geschrieben: {pfad} ({len(inhalt.encode())} B)" + (f", Kopie: {os.path.basename(sicherung)}" if sicherung else "")


def mit_token(app):
    """ASGI-Hülle: jede HTTP-Anfrage braucht 'Authorization: Bearer <MCP_TOKEN>' (außer /gesund)."""
    async def huelle(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        if scope.get("path") == "/gesund":
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
            return await send({"type": "http.response.body", "body": f"ok {VERSION}".encode()})
        kopf = dict(scope.get("headers") or []).get(b"authorization", b"").decode()
        if not kopf.startswith("Bearer ") or not hmac.compare_digest(kopf[7:].strip(), TOKEN):
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
            return await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
        return await app(scope, receive, send)
    return huelle


def main():
    if len(TOKEN) < 32:
        raise SystemExit("MCP_TOKEN fehlt oder ist kürzer als 32 Zeichen (z. B. openssl rand -hex 32)")
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        host="0.0.0.0",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    print(f"Unraid MCP {VERSION} auf Port {PORT}, Pfad /mcp", flush=True)
    uvicorn.run(mit_token(app), host="0.0.0.0", port=PORT, log_level="warning", proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
