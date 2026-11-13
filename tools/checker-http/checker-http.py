#!/usr/bin/env python3
"""Comprobacion remota y no intrusiva de exposicion a CVE-2026-119618.

Uso: python checker-http.py example.com

No ejecuta exploits. El estado POSIBLEMENTE_VULNERABLE no equivale a una
confirmacion: las cabeceras pueden ocultarse, modificarse o corresponder a
un proxy, y los proveedores pueden aplicar parches sin cambiar la version.
"""

import argparse
import html
import http.client
import json
import math
import os
import re
import shutil
import socket
import ssl
import sys
import textwrap
from urllib.parse import urlsplit


CVE = "CVE-2026-119618"
MIN_AFFECTED = (2, 4, 55)
MAX_AFFECTED = (2, 4, 70)
APACHE_VERSION = re.compile(r"^Apache/(\d+)\.(\d+)\.(\d+)(?=\s|\(|$)", re.I)
STATUS_VERSION = re.compile(r"\bServer\s*Version\s*:\s*(Apache/\d+\.\d+\.\d+)", re.I)
MAX_STATUS_BYTES = 12288


def parse_target(raw):
    if not raw or any(char.isspace() for char in raw):
        raise ValueError("Indica un dominio o URL sin espacios.")

    url = raw if "://" in raw else "https://" + raw
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Solo se aceptan direcciones HTTP o HTTPS validas.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("No incluyas credenciales en la URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("El puerto de la URL no es valido.") from exc

    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if port == 0:
        raise ValueError("El puerto debe estar entre 1 y 65535.")

    host = parsed.hostname
    shown_host = "[" + host + "]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    address = f"{parsed.scheme}://{shown_host}"
    if port != default_port:
        address += f":{port}"
    return parsed.scheme, host, port, address


def tls_context(insecure=False, alpn=None):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if alpn:
        context.set_alpn_protocols(alpn)
    return context


def detect_http2(host, port, timeout, insecure):
    """Solo negocia TLS/ALPN: no envía tramas HTTP/2 ni cargas especiales."""
    context = tls_context(insecure, ["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            return tls_socket.selected_alpn_protocol()


def new_http_connection(scheme, host, port, timeout, insecure):
    if scheme == "https":
        context = tls_context(insecure, ["http/1.1"])
        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=context
        )
    return http.client.HTTPConnection(host, port, timeout=timeout)


def read_server_header(scheme, host, port, timeout, insecure):
    connection = new_http_connection(scheme, host, port, timeout, insecure)

    try:
        connection.request(
            "HEAD", "/", headers={
                "User-Agent": "CVE-2026-119618-Checker/1.0",
                "Accept": "*/*",
                "Connection": "close",
            }
        )
        response = connection.getresponse()
        return response.status, response.getheader("Server", "")
    finally:
        connection.close()


def parse_apache_version(server_header):
    match = APACHE_VERSION.match(server_header.strip())
    return tuple(map(int, match.groups())) if match else None


def parse_status_version(data):
    """Extrae SOLO la version de una respuesta autentica de mod_status."""
    cleaned = html.unescape(re.sub(r"<[^>]+>", "\n", data))
    is_html_status = "apache server status for" in cleaned.lower()
    is_auto_status = (
        re.search(r"\bServerMPM\s*:", cleaned, re.I)
        and re.search(r"\b(BusyWorkers|IdleWorkers|Scoreboard)\s*:", cleaned, re.I)
    )
    if not is_html_status and not is_auto_status:
        return None
    match = STATUS_VERSION.search(cleaned)
    return parse_apache_version(match.group(1)) if match else None


def read_status_version(scheme, host, port, timeout, insecure, debug_notes):
    """Prueba el estado automatico y, si es necesario, el HTML convencional."""
    for path in ("/server-status?auto", "/server-status"):
        connection = new_http_connection(scheme, host, port, timeout, insecure)
        try:
            connection.request(
                "GET", path,
                headers={
                    "User-Agent": "CVE-2026-119618-Checker/1.1",
                    "Accept": "text/plain, text/html",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            debug_notes.append(f"{path}: HTTP {response.status}")
            if response.status != 200:
                continue
            content_type = response.getheader("Content-Type", "").lower()
            if content_type and not (
                "text/plain" in content_type or "text/html" in content_type
            ):
                debug_notes.append(f"{path}: formato no textual")
                continue
            body = response.read(MAX_STATUS_BYTES)
            version = parse_status_version(body.decode("utf-8", errors="replace"))
            if version:
                return version, path
            debug_notes.append(f"{path}: sin version verificable de mod_status")
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            debug_notes.append(f"{path}: {type(exc).__name__}")
        finally:
            connection.close()
    return None, None


def assess(version, http2_enabled, scheme):
    """Evalúa únicamente la versión anunciada y la exposición observada."""
    if version is None:
        return (
            "INDETERMINADO",
            "No se pudo identificar una version de Apache ni en Server "
            "ni en un mod_status accesible. Podria estar oculta o tras un proxy.",
        )

    if version < MIN_AFFECTED:
        return (
            "INDETERMINADO",
            "La version Apache observada es anterior al intervalo upstream "
            "(2.4.55 a 2.4.70), pero algunas distribuciones incorporan versiones "
            "mas nuevas de mod_http2 en paquetes antiguos. Verificar el modulo "
            "y el aviso de seguridad del fabricante antes de descartar el CVE.",
        )

    if version > MAX_AFFECTED:
        return (
            "NO_AFECTADO_POR_VERSION_OBSERVADA",
            "La version Apache observada esta fuera del intervalo afectado "
            "(2.4.55 a 2.4.70). Validar el paquete y los parches del fabricante; "
            "esto no verifica servidores de origen ocultos ni modulos externos.",
        )

    if scheme == "https" and http2_enabled is True:
        return (
            "POSIBLEMENTE_VULNERABLE",
            "La version Apache observada esta en el intervalo afectado y "
            "el endpoint negocia HTTP/2. NO esta confirmada la vulnerabilidad: "
            "verificar mod_http2, version del paquete y parches del fabricante.",
        )

    if scheme == "http":
        explanation = (
            "La version observada esta en el intervalo afectado, pero no "
            "se comprueba h2c (HTTP/2 sin TLS)."
        )
    elif http2_enabled is False:
        explanation = (
            "La version observada esta en el intervalo afectado, pero no "
            "se negocio HTTP/2 por TLS en esta conexion."
        )
    else:
        explanation = (
            "La version observada esta en el intervalo afectado, pero "
            "no fue posible comprobar HTTP/2."
        )
    return "INDETERMINADO", explanation + " Validar configuracion y parches."


def check_target(target, timeout=5.0, insecure=False, debug=False):
    scheme, host, port, address = parse_target(target)
    alpn, alpn_error, response_code, server_header, header_error = (
        None, None, None, "", None
    )
    debug_notes = []

    if scheme == "https":
        try:
            alpn = detect_http2(host, port, timeout, insecure)
        except (OSError, ssl.SSLError) as exc:
            alpn_error = str(exc)

    try:
        response_code, server_header = read_server_header(
            scheme, host, port, timeout, insecure
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        header_error = str(exc)

    version = parse_apache_version(server_header)
    source = "cabecera Server" if version else None
    if version is None and (not header_error or scheme == "https" and not alpn_error):
        status_version, status_source = read_status_version(
            scheme, host, port, timeout, insecure, debug_notes
        )
        if status_version is not None:
            version, source = status_version, status_source

    if header_error and version is None and (scheme == "http" or alpn_error):
        status = "ERROR_CONEXION"
        detail = "No se pudo obtener evidencia del endpoint. " + header_error
    else:
        http2_enabled = (alpn == "h2") if alpn_error is None else None
        status, detail = assess(version, http2_enabled, scheme)
        if header_error:
            detail += " No se obtuvo cabecera Server: " + header_error
        if alpn_error:
            detail += " Fallo la comprobacion ALPN: " + alpn_error

    return {
        "cve": CVE,
        "objetivo": address,
        "http_status": response_code,
        "server": server_header or None,
        "apache_version": ".".join(map(str, version)) if version else None,
        "fuente_version": source,
        "http2_tls": (alpn == "h2") if scheme == "https" and not alpn_error else None,
        "resultado": status,
        "detalle": detail,
        **({"debug": debug_notes} if debug else {}),
    }


def color_enabled(mode):
    """ANSI automatico en terminal; nunca colorear JSON."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    return (
        sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "").lower() != "dumb"
    )


def render_report(result, color=False, width=None):
    """Panel ASCII legible incluso en terminales con problemas UTF-8."""
    width = width or min(90, max(40, shutil.get_terminal_size((80, 24)).columns - 1))
    inner_width = width - 4
    lines = []

    def paint(value, code):
        return f"\033[{code}m{value}\033[0m" if color and code else value

    def box_line(segments):
        visible = sum(len(value) for value, _ in segments)
        padding = " " * max(0, inner_width - visible)
        body = "".join(paint(value, code) for value, code in segments)
        lines.append(paint("|", "36") + " " + body + padding + " " + paint("|", "36"))

    def border():
        lines.append(paint("+" + "-" * (width - 2) + "+", "36"))

    def plain_line(value, style=""):
        for fragment in textwrap.wrap(value, width=inner_width, break_on_hyphens=False) or [""]:
            box_line([(fragment, style)])

    def field(label, value, value_style="1;37"):
        label_width = 13
        capacity = inner_width - label_width
        fragments = textwrap.wrap(
            str(value), width=max(1, capacity), break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        for index, fragment in enumerate(fragments):
            heading = f"{label if index == 0 else '':<{label_width}}"
            box_line([(heading, "90"), (fragment, value_style)])

    statuses = {
        "NO_AFECTADO_POR_VERSION_OBSERVADA": ("[OK] NO AFECTADO POR VERSION OBSERVADA", "1;32"),
        "POSIBLEMENTE_VULNERABLE": ("[!] POSIBLEMENTE VULNERABLE", "1;31"),
        "INDETERMINADO": ("[?] INDETERMINADO", "1;33"),
        "ERROR_CONEXION": ("[X] ERROR DE CONEXION", "1;31"),
    }
    status_text, status_color = statuses[result["resultado"]]
    server = (
        "Apache/" + result["apache_version"]
        if result["apache_version"] else result["server"] or "No identificado"
    )
    h2 = result["http2_tls"]
    h2_text = "SI" if h2 is True else "NO" if h2 is False else "NO VERIFICADO"
    h2_color = "1;36" if h2 is True else "1;32" if h2 is False else "1;33"

    border()
    plain_line("APACHE HTTP SERVER  |  CVE-2026-119618", "1;36")
    plain_line("REMOTE EXPOSURE CHECKER  -  READ ONLY", "90")
    border()
    field("OBJETIVO", result["objetivo"])
    field("SERVIDOR", server, "1;36")
    field("FUENTE", result["fuente_version"] or "No identificada", "37")
    field("HTTP/2 TLS", h2_text, h2_color)
    border()
    field("RESULTADO", status_text, status_color)
    field("DETALLE", result["detalle"], "37")
    border()
    if "debug" in result:
        for entry in result["debug"]:
            lines.append(paint("[DEBUG] ", "90") + entry)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=f"Checker remoto no intrusivo para {CVE}."
    )
    parser.add_argument("target", help="Dominio o URL, por ejemplo example.com")
    parser.add_argument("--timeout", type=float, default=5.0, help="Segundos (5)")
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="No verificar certificado TLS (solo entornos autorizados)",
    )
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto",
        help="Colores ANSI en terminal: auto (por defecto), always o never",
    )
    parser.add_argument("--debug", action="store_true", help="Muestra estados HTTP de las pruebas")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout debe estar entre 0 y 60 segundos.")

    try:
        result = check_target(args.target, args.timeout, args.insecure, args.debug)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(render_report(result, color=color_enabled(args.color)))

    return {
        "NO_AFECTADO_POR_VERSION_OBSERVADA": 0,
        "POSIBLEMENTE_VULNERABLE": 1,
        "INDETERMINADO": 2,
        "ERROR_CONEXION": 3,
    }[result["resultado"]]


if __name__ == "__main__":
    sys.exit(main())
