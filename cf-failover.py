#!/usr/bin/env python3
"""
cf-failover — conmuta el proxy de Cloudflare (nube naranja/gris) de los dominios
gestionados segun la lista publica de IPs bloqueadas por los ISP españoles.

Regla: si el par de IPs anycast que Cloudflare asigna a una zona aparece en la
lista, esa zona pasa a GRIS (proxied=false) y resuelve directa al origen. Cuando
la lista la da por libre CLEAR_CONFIRMATIONS ciclos seguidos y la sonda TCP
confirma que se alcanza, vuelve a NARANJA.

INVARIANTE: solo se toca el campo `proxied` (y el `ttl`) via PATCH parcial. El
`content` del registro NUNCA se escribe, para no pisar la IP dinamica que
actualice el router o un cliente DDNS.
"""

import argparse
import fcntl
import ipaddress
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def resolve_base_dir():
    """
    Donde viven config.env y zones.conf, por orden: la variable CF_FAILOVER_HOME,
    el propio directorio del script si contiene la config (instalacion "en sitio"),
    y si no /etc/cf-failover.
    """
    override = os.environ.get("CF_FAILOVER_HOME")
    if override:
        return override
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if os.path.exists(os.path.join(script_dir, "config.env")):
        return script_dir
    return "/etc/cf-failover"


BASE_DIR = resolve_base_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "config.env")
ZONES_FILE = os.path.join(BASE_DIR, "zones.conf")
STATE_DIR = os.environ.get("CF_FAILOVER_STATE", "/var/lib/cf-failover")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
TRANSITIONS_LOG = os.path.join(STATE_DIR, "transitions.log")
LOCK_FILE = os.path.join(STATE_DIR, "lock")

CF_API = "https://api.cloudflare.com/client/v4"

# Tipos de registro que apuntan a un host y por tanto pueden ir proxiados.
SWITCHABLE_TYPES = ("A", "AAAA", "CNAME")

# Cloudflare rechaza quitar la nube al registro que sea fallback origin de SSL
# for SaaS. Se detecta por este codigo y se excluye solo a partir de entonces.
FALLBACK_ORIGIN_ERROR = 1040

POLICIES = ("hold", "probe", "orange", "grey")

DEFAULTS = {
    "BLOCKLIST_URL": "https://hayahora.futbol/estado/blocked-any.txt",
    "BLOCKLIST_ERROR_POLICY": "hold",
    "CLEAR_CONFIRMATIONS": "2",
    "RESOLVER": "1.1.1.1",
    "PROBE_ENABLED": "1",
    "PROBE_TIMEOUT": "4",
    "GREY_TTL": "60",
    "HTTP_TIMEOUT": "15",
}


def log(message):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", flush=True)


def log_transition(message):
    """Historico persistente de cambios de modo (el journal rota y se pierde)."""
    log(message)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(TRANSITIONS_LOG, "a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
    except OSError as error:
        log(f"WARN no se pudo escribir el historico: {error}")


def load_config():
    config = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip().strip('"').strip("'")
    except OSError as error:
        sys.exit(f"ERROR no se puede leer {CONFIG_FILE}: {error}")

    if not config.get("CF_API_TOKEN"):
        sys.exit("ERROR falta CF_API_TOKEN en la configuracion")

    policy = config["BLOCKLIST_ERROR_POLICY"].strip().lower()
    if policy not in POLICIES:
        log(f"WARN BLOCKLIST_ERROR_POLICY={policy!r} no es valida ({'/'.join(POLICIES)}); se usa 'hold'")
        policy = "hold"
    config["BLOCKLIST_ERROR_POLICY"] = policy

    return config


def load_zones():
    """
    Formato: un dominio por linea, con exclusiones opcionales tras una barra.

        ejemplo.com
        otro.com|interno.otro.com,otro-mas.otro.com

    Ni zone_id ni record_id: se descubren solos contra la API.
    """
    zones = []
    try:
        with open(ZONES_FILE, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = [part.strip() for part in line.split("|")]
                apex = parts[0].lower()
                excluded = set()
                if len(parts) > 1 and parts[1]:
                    excluded = {h.strip().lower() for h in parts[1].split(",") if h.strip()}
                zones.append({"apex": apex, "excluded": excluded})
    except OSError as error:
        sys.exit(f"ERROR no se puede leer {ZONES_FILE}: {error}")

    if not zones:
        sys.exit("ERROR no hay dominios configurados")
    return zones


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)


def fetch_blocklist(config):
    """
    Devuelve un set de IPs bloqueadas, o None si la respuesta no es fiable.

    None significa "no se sabe" y lo que se haga entonces lo decide
    BLOCKLIST_ERROR_POLICY.

    Un set VACIO si es un estado legitimo y frecuente: fuera de las ventanas de
    bloqueo no hay ninguna IP bloqueada. No se puede tratar como error, porque
    entonces una zona en gris no volveria nunca a naranja justo cuando ya no hay
    bloqueo. La red de seguridad contra un fichero vacio por averia de la fuente
    es la sonda TCP, obligatoria antes de reactivar la nube.
    """
    url = config["BLOCKLIST_URL"]
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "cf-failover/1.0"})
        with urllib.request.urlopen(request, timeout=int(config["HTTP_TIMEOUT"])) as response:
            if response.status != 200:
                log(f"WARN la lista respondio HTTP {response.status}")
                return None
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, socket.timeout, OSError) as error:
        log(f"WARN no se pudo descargar la lista ({error})")
        return None

    entries = set()
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            log(f"WARN la lista trae una entrada que no es una IP ({line!r})")
            return None
        entries.add(line)

    return entries


def cf_request(config, method, path, payload=None):
    """Devuelve el JSON de Cloudflare (tambien en los errores, para poder leer el codigo)."""
    url = f"{CF_API}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {config['CF_API_TOKEN']}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=int(config["HTTP_TIMEOUT"])) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            return json.loads(error.read().decode("utf-8"))
        except (ValueError, OSError):
            log(f"ERROR API Cloudflare {method} {path}: HTTP {error.code}")
    except (urllib.error.URLError, socket.timeout, OSError) as error:
        log(f"ERROR API Cloudflare {method} {path}: {error}")
    return None


def error_codes(result):
    if not result:
        return []
    return [e.get("code") for e in result.get("errors", [])]


def get_zone_id(config, zone, entry):
    """El id de la zona se resuelve por nombre una vez y se memoriza."""
    if entry.get("zone_id"):
        return entry["zone_id"]
    result = cf_request(config, "GET", f"/zones?name={zone['apex']}")
    if not result or not result.get("success") or not result.get("result"):
        log(f"{zone['apex']}: no se encuentra la zona en Cloudflare (¿el token la incluye?)")
        return None
    entry["zone_id"] = result["result"][0]["id"]
    return entry["zone_id"]


def list_records(config, zone_id):
    result = cf_request(config, "GET", f"/zones/{zone_id}/dns_records?per_page=100")
    if not result or not result.get("success"):
        return None
    return result["result"]


def points_to_same_origin(record, apex, apex_origins):
    """
    Solo se conmutan los registros que apuntan al MISMO sitio que el dominio
    principal: registros A/AAAA con su misma IP, o CNAME dentro de la propia zona.

    Un `webmail` o un `autodiscover` que sean CNAME al proveedor de correo apuntan
    a un servidor ajeno: quitarles la nube los mandaria directos a un origen que
    quiza no tenga certificado para ese nombre. No son cosa nuestra.
    """
    if record["type"] in ("A", "AAAA"):
        return record["content"] in apex_origins
    target = record["content"].lower().rstrip(".")
    return target == apex or target.endswith("." + apex)


def select_records(zone, entry, records):
    """
    Que registros conmutar.

    En NARANJA se descubren solos: los proxiados de la zona que apuntan al mismo
    origen, menos las exclusiones. En GRIS ya no se distinguen de los que el
    usuario quiere grises a proposito, asi que se usa la lista memorizada.
    """
    skip = set(entry.get("skip", []))
    excluded = zone["excluded"]
    apex = zone["apex"]
    apex_origins = {
        r["content"] for r in records
        if r["name"].lower() == apex and r["type"] in ("A", "AAAA")
    }

    candidates = [
        r for r in records
        if r["type"] in SWITCHABLE_TYPES
        and r["name"].lower() not in excluded
        and r["id"] not in skip
        and points_to_same_origin(r, apex, apex_origins)
    ]

    proxied = [r for r in candidates if r.get("proxied")]
    if proxied:
        entry["record_ids"] = [r["id"] for r in proxied]
        return proxied, True

    remembered = set(entry.get("record_ids", []))
    return [r for r in candidates if r["id"] in remembered], False


def set_proxied(config, zone_id, records, entry, proxied, dry_run):
    """PATCH parcial: solo `proxied` y `ttl`. Nunca se envia `content`."""
    ttl = 1 if proxied else int(config["GREY_TTL"])
    payload = {"proxied": proxied, "ttl": ttl}
    changed = False
    for record in records:
        if dry_run:
            log(f"  [dry-run] {record['name']} -> proxied={proxied} ttl={ttl}")
            changed = True
            continue
        result = cf_request(config, "PATCH", f"/zones/{zone_id}/dns_records/{record['id']}", payload)
        if result and result.get("success"):
            log(f"  {record['name']} -> proxied={proxied} ttl={ttl}")
            changed = True
        elif FALLBACK_ORIGIN_ERROR in error_codes(result):
            # Es el fallback origin de SSL for SaaS: debe seguir proxiado siempre.
            # No es un fallo que reintentar, asi que se excluye de aqui en adelante.
            entry.setdefault("skip", [])
            if record["id"] not in entry["skip"]:
                entry["skip"].append(record["id"])
            entry["record_ids"] = [i for i in entry.get("record_ids", []) if i != record["id"]]
            log(f"  {record['name']}: es el fallback origin de Cloudflare for SaaS, "
                f"debe seguir proxiado; se excluye")
        else:
            log(f"  ERROR no se pudo cambiar {record['name']}")
    return changed


def resolve_public(config, hostname):
    """Resuelve contra un resolver publico (el del sistema puede cachear distinto)."""
    try:
        output = subprocess.run(
            ["dig", "+short", f"@{config['RESOLVER']}", hostname, "A"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
    except (subprocess.SubprocessError, OSError) as error:
        log(f"WARN fallo al resolver {hostname}: {error}")
        return []

    addresses = []
    for line in output.splitlines():
        candidate = line.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        addresses.append(candidate)
    return addresses


def tcp_reachable(address, timeout):
    try:
        with socket.create_connection((address, 443), timeout=timeout):
            return True
    except OSError:
        return False


def zone_snapshot(config, zone, state):
    """Lee de Cloudflare, en una sola llamada, todo lo que hace falta de una zona."""
    entry = state.setdefault(zone["apex"], {"cf_ips": [], "clear_streak": 0})

    zone_id = get_zone_id(config, zone, entry)
    if not zone_id:
        return None

    records = list_records(config, zone_id)
    if records is None:
        log(f"{zone['apex']}: no se pudieron leer los registros; se omite este ciclo")
        return None

    managed, proxied = select_records(zone, entry, records)
    if not managed:
        log(f"{zone['apex']}: no hay registros que conmutar")
        return None

    origin_ips = {r["content"] for r in managed if r["type"] in ("A", "AAAA")}
    return {"entry": entry, "zone_id": zone_id, "records": managed,
            "proxied": proxied, "origin_ips": origin_ips}


def remember_cf_ips(config, zone, snap):
    """
    En naranja lo que resuelve son las IPs anycast de la zona: se memorizan,
    porque en gris dejan de ser visibles y sin ellas no se sabe cuando volver.
    """
    resolved = [ip for ip in resolve_public(config, zone["apex"]) if ip not in snap["origin_ips"]]
    if resolved and sorted(resolved) != sorted(snap["entry"].get("cf_ips", [])):
        log(f"{zone['apex']}: IPs de Cloudflare -> {', '.join(sorted(resolved))}")
    if resolved:
        snap["entry"]["cf_ips"] = resolved


def probe_unreachable(config, cf_ips):
    timeout = int(config["PROBE_TIMEOUT"])
    return [ip for ip in cf_ips if not tcp_reachable(ip, timeout)]


def process_zone(config, zone, blocklist, state, dry_run):
    apex = zone["apex"]
    snap = zone_snapshot(config, zone, state)
    if snap is None:
        return
    entry = snap["entry"]

    if snap["proxied"]:
        remember_cf_ips(config, zone, snap)

    cf_ips = entry.get("cf_ips", [])
    if not cf_ips:
        log(f"{apex}: aun no se conoce su par de IPs de Cloudflare; se omite")
        return

    blocked = sorted(ip for ip in cf_ips if ip in blocklist)

    if blocked:
        entry["clear_streak"] = 0
        if snap["proxied"]:
            if set_proxied(config, snap["zone_id"], snap["records"], entry, False, dry_run):
                log_transition(f"{apex}: BLOQUEADA ({', '.join(blocked)}) -> pasa a GRIS")
        else:
            log(f"{apex}: sigue bloqueada ({', '.join(blocked)}), se mantiene en gris")
        return

    if snap["proxied"]:
        entry["clear_streak"] = 0
        log(f"{apex}: naranja y sin bloqueo ({', '.join(cf_ips)})")
        return

    # Gris y la lista la da por libre: se confirma varios ciclos antes de volver,
    # para no rebotar en mitad de una ventana de bloqueo.
    entry["clear_streak"] = entry.get("clear_streak", 0) + 1
    needed = int(config["CLEAR_CONFIRMATIONS"])
    if entry["clear_streak"] < needed:
        log(f"{apex}: gris, libre en la lista ({entry['clear_streak']}/{needed} confirmaciones)")
        return

    if config["PROBE_ENABLED"] == "1":
        unreachable = probe_unreachable(config, cf_ips)
        if unreachable:
            entry["clear_streak"] = 0
            log(f"{apex}: libre en la lista pero la sonda no alcanza {', '.join(unreachable)}; sigue en gris")
            return

    if set_proxied(config, snap["zone_id"], snap["records"], entry, True, dry_run):
        log_transition(f"{apex}: LIBRE ({', '.join(cf_ips)}) -> vuelve a NARANJA")
        entry["clear_streak"] = 0


def process_zone_offline(config, zone, state, dry_run):
    """
    Ciclo cuando la lista no esta disponible. Que hacer lo decide
    BLOCKLIST_ERROR_POLICY: 'probe' usa solo la sonda TCP local, 'orange'/'grey'
    fuerzan un modo fijo. ('hold' no llega hasta aqui.)
    """
    policy = config["BLOCKLIST_ERROR_POLICY"]
    apex = zone["apex"]
    snap = zone_snapshot(config, zone, state)
    if snap is None:
        return
    entry = snap["entry"]

    if policy == "orange":
        if not snap["proxied"] and set_proxied(config, snap["zone_id"], snap["records"], entry, True, dry_run):
            log_transition(f"{apex}: sin lista, politica 'orange' -> vuelve a NARANJA")
        return

    if policy == "grey":
        if snap["proxied"] and set_proxied(config, snap["zone_id"], snap["records"], entry, False, dry_run):
            log_transition(f"{apex}: sin lista, politica 'grey' -> pasa a GRIS")
        return

    if snap["proxied"]:
        remember_cf_ips(config, zone, snap)

    cf_ips = entry.get("cf_ips", [])
    if not cf_ips:
        log(f"{apex}: sin lista y sin par de IPs memorizado; no se toca nada")
        return

    unreachable = probe_unreachable(config, cf_ips)

    if unreachable:
        entry["clear_streak"] = 0
        if snap["proxied"] and set_proxied(config, snap["zone_id"], snap["records"], entry, False, dry_run):
            log_transition(f"{apex}: sin lista, la sonda no alcanza {', '.join(unreachable)} -> pasa a GRIS")
        return

    if snap["proxied"]:
        entry["clear_streak"] = 0
        log(f"{apex}: sin lista, naranja y la sonda alcanza sus IPs")
        return

    entry["clear_streak"] = entry.get("clear_streak", 0) + 1
    needed = int(config["CLEAR_CONFIRMATIONS"])
    if entry["clear_streak"] < needed:
        log(f"{apex}: sin lista, la sonda alcanza sus IPs ({entry['clear_streak']}/{needed} confirmaciones)")
        return

    if set_proxied(config, snap["zone_id"], snap["records"], entry, True, dry_run):
        log_transition(f"{apex}: sin lista, la sonda alcanza {', '.join(cf_ips)} -> vuelve a NARANJA")
        entry["clear_streak"] = 0


def command_status(config, zones, state):
    for zone in zones:
        snap = zone_snapshot(config, zone, state)
        if snap is None:
            print(f"{zone['apex']:<24} (no se pudo consultar)")
            continue
        entry = snap["entry"]
        mode = "NARANJA" if snap["proxied"] else "GRIS"
        cf_ips = ", ".join(entry.get("cf_ips", [])) or "(sin memorizar)"
        names = ", ".join(sorted(r["name"] for r in snap["records"]))
        print(f"{zone['apex']:<24} {mode:<8} ips=[{cf_ips}]")
        print(f"{'':<24} conmuta: {names}")


def command_force(config, zones, state, proxied, dry_run):
    for zone in zones:
        snap = zone_snapshot(config, zone, state)
        if snap is None:
            continue
        if set_proxied(config, snap["zone_id"], snap["records"], snap["entry"], proxied, dry_run):
            log_transition(f"{zone['apex']}: forzado manual -> {'NARANJA' if proxied else 'GRIS'}")


def main():
    parser = argparse.ArgumentParser(description="Conmuta el proxy de Cloudflare segun la lista de IPs bloqueadas")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true", help="muestra el estado actual y sale")
    group.add_argument("--force-grey", action="store_true", help="fuerza gris")
    group.add_argument("--force-orange", action="store_true", help="fuerza naranja")
    parser.add_argument("--dry-run", action="store_true", help="no escribe en Cloudflare, solo informa")
    parser.add_argument("--zone", metavar="DOMINIO", help="limita la accion a un dominio de zones.conf")
    args = parser.parse_args()

    config = load_config()
    zones = load_zones()

    if args.zone:
        zones = [z for z in zones if z["apex"] == args.zone.lower()]
        if not zones:
            sys.exit(f"ERROR el dominio {args.zone} no esta en {ZONES_FILE}")

    os.makedirs(STATE_DIR, exist_ok=True)
    lock = open(LOCK_FILE, "w", encoding="utf-8")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("otra ejecucion sigue en curso; se omite este ciclo")
        return 0

    state = load_state()

    if args.status:
        command_status(config, zones, state)
        save_state(state)
        return 0

    if args.force_grey or args.force_orange:
        command_force(config, zones, state, args.force_orange, args.dry_run)
        if not args.dry_run:
            save_state(state)
        return 0

    blocklist = fetch_blocklist(config)

    if blocklist is None:
        policy = config["BLOCKLIST_ERROR_POLICY"]
        if policy == "hold":
            log("lista no disponible y politica 'hold': no se toca nada")
            return 0
        log(f"lista no disponible; se aplica la politica '{policy}'")
        for zone in zones:
            process_zone_offline(config, zone, state, args.dry_run)
    else:
        for zone in zones:
            process_zone(config, zone, blocklist, state, args.dry_run)

    if not args.dry_run:
        save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
