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
actualiza el router.
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
    """Formato: apex|zone_id|record_id[,record_id...]"""
    zones = []
    try:
        with open(ZONES_FILE, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [part.strip() for part in line.split("|")]
                if len(parts) != 3:
                    log(f"WARN linea ignorada en zones.conf: {line}")
                    continue
                apex, zone_id, record_ids = parts
                zones.append({
                    "apex": apex,
                    "zone_id": zone_id,
                    "record_ids": [r.strip() for r in record_ids.split(",") if r.strip()],
                })
    except OSError as error:
        sys.exit(f"ERROR no se puede leer {ZONES_FILE}: {error}")

    if not zones:
        sys.exit("ERROR no hay zonas configuradas")
    return zones


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)


def fetch_blocklist(config):
    """
    Devuelve un set de IPs bloqueadas, o None si la respuesta no es fiable.

    None significa "no se sabe" y el llamante NO debe tocar nada.

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
                log(f"WARN la lista respondio HTTP {response.status}; no se toca nada")
                return None
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, socket.timeout, OSError) as error:
        log(f"WARN no se pudo descargar la lista ({error}); no se toca nada")
        return None

    entries = set()
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            log(f"WARN la lista trae una entrada que no es una IP ({line!r}); no se toca nada")
            return None
        entries.add(line)

    return entries


def cf_request(config, method, path, payload=None):
    url = f"{CF_API}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {config['CF_API_TOKEN']}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=int(config["HTTP_TIMEOUT"])) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:300]
        log(f"ERROR API Cloudflare {method} {path}: HTTP {error.code} {detail}")
    except (urllib.error.URLError, socket.timeout, OSError) as error:
        log(f"ERROR API Cloudflare {method} {path}: {error}")
    return None


def get_record(config, zone_id, record_id):
    result = cf_request(config, "GET", f"/zones/{zone_id}/dns_records/{record_id}")
    if not result or not result.get("success"):
        return None
    return result.get("result")


def set_proxied(config, zone, proxied, dry_run):
    """PATCH parcial: solo `proxied` y `ttl`. Nunca se envia `content`."""
    ttl = 1 if proxied else int(config["GREY_TTL"])
    payload = {"proxied": proxied, "ttl": ttl}
    ok = True
    for record_id in zone["record_ids"]:
        if dry_run:
            log(f"  [dry-run] PATCH {zone['apex']} record={record_id} proxied={proxied} ttl={ttl}")
            continue
        result = cf_request(config, "PATCH", f"/zones/{zone['zone_id']}/dns_records/{record_id}", payload)
        if not result or not result.get("success"):
            log(f"  ERROR no se pudo cambiar el registro {record_id} de {zone['apex']}")
            ok = False
        else:
            log(f"  registro {result['result']['name']} -> proxied={proxied} ttl={ttl}")
    return ok


def resolve_public(config, hostname):
    """Resuelve contra un resolver publico (no el del sistema, que puede cachear distinto)."""
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


def process_zone(config, zone, blocklist, state, dry_run):
    apex = zone["apex"]
    entry = state.setdefault(apex, {"cf_ips": [], "clear_streak": 0})

    record = get_record(config, zone["zone_id"], zone["record_ids"][0])
    if record is None:
        log(f"{apex}: no se pudo leer el estado en Cloudflare; se omite este ciclo")
        return
    proxied = bool(record.get("proxied"))
    origin_ip = record.get("content", "")
    mode = "naranja" if proxied else "gris"

    if proxied:
        # En naranja lo que resuelve son las IPs anycast de la zona: se memorizan,
        # porque en gris dejan de ser visibles y sin ellas no se sabe cuando volver.
        resolved = [ip for ip in resolve_public(config, apex) if ip != origin_ip]
        if resolved:
            if sorted(resolved) != sorted(entry.get("cf_ips", [])):
                log(f"{apex}: par de IPs de Cloudflare actualizado -> {', '.join(sorted(resolved))}")
            entry["cf_ips"] = resolved

    cf_ips = entry.get("cf_ips", [])
    if not cf_ips:
        log(f"{apex}: modo {mode}, aun no se conoce su par de IPs de Cloudflare; se omite")
        return

    blocked = sorted(ip for ip in cf_ips if ip in blocklist)

    if blocked:
        entry["clear_streak"] = 0
        if proxied:
            if set_proxied(config, zone, False, dry_run):
                log_transition(f"{apex}: BLOQUEADA ({', '.join(blocked)}) -> pasa a GRIS")
            else:
                log(f"{apex}: BLOQUEADA ({', '.join(blocked)}) pero NO se pudo pasar a gris")
        else:
            log(f"{apex}: sigue bloqueada ({', '.join(blocked)}), se mantiene en gris")
        return

    if proxied:
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
        timeout = int(config["PROBE_TIMEOUT"])
        unreachable = [ip for ip in cf_ips if not tcp_reachable(ip, timeout)]
        if unreachable:
            entry["clear_streak"] = 0
            log(f"{apex}: la lista la da libre pero la sonda no alcanza {', '.join(unreachable)}; sigue en gris")
            return

    if set_proxied(config, zone, True, dry_run):
        log_transition(f"{apex}: LIBRE ({', '.join(cf_ips)}) -> vuelve a NARANJA")
        entry["clear_streak"] = 0
    else:
        log(f"{apex}: libre pero NO se pudo volver a naranja; se reintenta el proximo ciclo")


def process_zone_offline(config, zone, state, dry_run):
    """
    Ciclo cuando la lista no esta disponible. Que hacer lo decide
    BLOCKLIST_ERROR_POLICY, porque la respuesta correcta depende de la
    instalacion: 'hold' no toca nada, 'probe' decide con la sonda TCP local,
    'orange'/'grey' fuerzan un modo fijo.
    """
    policy = config["BLOCKLIST_ERROR_POLICY"]
    apex = zone["apex"]
    entry = state.setdefault(apex, {"cf_ips": [], "clear_streak": 0})

    record = get_record(config, zone["zone_id"], zone["record_ids"][0])
    if record is None:
        log(f"{apex}: no se pudo leer el estado en Cloudflare; se omite este ciclo")
        return
    proxied = bool(record.get("proxied"))

    if policy == "orange":
        if not proxied and set_proxied(config, zone, True, dry_run):
            log_transition(f"{apex}: sin lista, politica 'orange' -> vuelve a NARANJA")
        return

    if policy == "grey":
        if proxied and set_proxied(config, zone, False, dry_run):
            log_transition(f"{apex}: sin lista, politica 'grey' -> pasa a GRIS")
        return

    # policy == "probe": la sonda local pasa a ser la unica señal.
    if proxied:
        origin_ip = record.get("content", "")
        resolved = [ip for ip in resolve_public(config, apex) if ip != origin_ip]
        if resolved:
            entry["cf_ips"] = resolved

    cf_ips = entry.get("cf_ips", [])
    if not cf_ips:
        log(f"{apex}: sin lista y sin par de IPs memorizado; no se toca nada")
        return

    timeout = int(config["PROBE_TIMEOUT"])
    unreachable = [ip for ip in cf_ips if not tcp_reachable(ip, timeout)]

    if unreachable:
        entry["clear_streak"] = 0
        if proxied and set_proxied(config, zone, False, dry_run):
            log_transition(f"{apex}: sin lista, la sonda no alcanza {', '.join(unreachable)} -> pasa a GRIS")
        return

    if proxied:
        entry["clear_streak"] = 0
        log(f"{apex}: sin lista, naranja y la sonda alcanza sus IPs")
        return

    entry["clear_streak"] = entry.get("clear_streak", 0) + 1
    needed = int(config["CLEAR_CONFIRMATIONS"])
    if entry["clear_streak"] < needed:
        log(f"{apex}: sin lista, la sonda alcanza sus IPs ({entry['clear_streak']}/{needed} confirmaciones)")
        return

    if set_proxied(config, zone, True, dry_run):
        log_transition(f"{apex}: sin lista, la sonda alcanza {', '.join(cf_ips)} -> vuelve a NARANJA")
        entry["clear_streak"] = 0


def command_status(config, zones, state):
    for zone in zones:
        apex = zone["apex"]
        record = get_record(config, zone["zone_id"], zone["record_ids"][0])
        mode = "desconocido"
        if record is not None:
            mode = "NARANJA" if record.get("proxied") else "GRIS"
        entry = state.get(apex, {})
        cf_ips = ", ".join(entry.get("cf_ips", [])) or "(sin memorizar)"
        print(f"{apex:<20} modo={mode:<9} registros={len(zone['record_ids'])} "
              f"ips_cloudflare=[{cf_ips}] racha_libre={entry.get('clear_streak', 0)}")


def command_force(config, zones, proxied, dry_run):
    for zone in zones:
        log_transition(f"{zone['apex']}: forzado manual -> {'NARANJA' if proxied else 'GRIS'}")
        set_proxied(config, zone, proxied, dry_run)


def main():
    parser = argparse.ArgumentParser(description="Conmuta el proxy de Cloudflare segun la lista de IPs bloqueadas")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true", help="muestra el estado actual y sale")
    group.add_argument("--force-grey", action="store_true", help="fuerza gris en todas las zonas")
    group.add_argument("--force-orange", action="store_true", help="fuerza naranja en todas las zonas")
    parser.add_argument("--dry-run", action="store_true", help="no escribe en Cloudflare, solo informa")
    parser.add_argument("--zone", metavar="APEX", help="limita la accion a una zona de zones.conf")
    args = parser.parse_args()

    config = load_config()
    zones = load_zones()

    if args.zone:
        zones = [zone for zone in zones if zone["apex"] == args.zone]
        if not zones:
            sys.exit(f"ERROR la zona {args.zone} no esta en {ZONES_FILE}")

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
        return 0

    if args.force_grey or args.force_orange:
        command_force(config, zones, args.force_orange, args.dry_run)
        return 0

    blocklist = fetch_blocklist(config)

    if blocklist is None:
        policy = config["BLOCKLIST_ERROR_POLICY"]
        if policy == "hold":
            log("lista no disponible y politica 'hold': no se toca nada")
        else:
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
