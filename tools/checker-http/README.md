# Checker HTTP — NIGHT CREW

Ayuda a los clientes a revisar indicios de exposición a **CVE-2026-119618** en Apache HTTP Server. Consulta la versión anunciada y negocia HTTP/2 mediante TLS/ALPN. Sirve para priorizar la revisión del servidor; la confirmación requiere comprobar el módulo y los parches instalados.

Usa Python 3 y su biblioteca estándar, sin dependencias de `pip` ni permisos de administrador. Envía un `HEAD /` y, si no obtiene una versión, hasta dos `GET` a `/server-status`. No sigue redirecciones. La negociación ALPN no envía tramas HTTP/2 ni ejecuta el exploit.

## Uso desde Linux

Descarga el archivo, revisa su contenido y ejecútalo con un dominio propio o autorizado:

```sh
curl --fail --show-error --location \
  https://raw.githubusercontent.com/NIGHTCREW-CL/CTI/main/tools/checker-http/checker-http.py \
  --output checker-http.py
less checker-http.py
python3 checker-http.py example.com
```

```sh
# Puerto específico y detalle de las consultas
python3 checker-http.py https://example.com:8443 --debug

# Salida JSON para revisión interna
python3 checker-http.py example.com --json

# Tiempo de espera por operación y salida sin colores
python3 checker-http.py example.com --timeout 10 --color never

# Ayuda completa
python3 checker-http.py --help
```

Sin esquema se utiliza HTTPS. Aunque se indique una ruta, las consultas se realizan sobre `/` y `/server-status` del host y puerto indicados. `--timeout` acepta un número mayor que 0 y hasta 60 segundos por operación; no es un límite total. `-k` omite la validación del certificado TLS y debe reservarse para certificados de laboratorio verificados por otra vía.

## Cómo interpretar el resultado

| Resultado | Significado | Código de salida |
| :--- | :--- | :---: |
| `POSIBLEMENTE_VULNERABLE` | Versión anunciada entre 2.4.55 y 2.4.70 y negociación HTTP/2. Revisar paquete, módulo y parches. | 1 |
| `INDETERMINADO` | Faltan evidencias, no se comprueba HTTP/2 o la versión es anterior al rango y puede incorporar un módulo actualizado por la distribución. | 2 |
| `NO_AFECTADO_POR_VERSION_OBSERVADA` | Versión anunciada posterior al rango upstream. No certifica la seguridad del servidor ni del origen. | 0 |
| `ERROR_CONEXION` | No se pudo obtener evidencia del endpoint. | 3 |

Una cabecera puede estar oculta o modificada. Un proxy puede negociar HTTP/2 mientras el origen usa otro protocolo. El script no comprueba HTTP/2 sin TLS (`h2c`), módulos externos ni revisiones de paquetes. Un resultado indeterminado o un HTTP/2 no negociado exige revisión local.

## Verificación desde la consola del servidor

Si tienes acceso por SSH, sigue la [guía de verificación local en Linux](VERIFICACION-LINUX.md). Incluye comandos para consultar versión, módulos, virtual hosts, protocolos y paquetes instalados, sin cambiar la configuración ni reiniciar servicios.

## Privacidad y referencia

El script no incluye credenciales ni objetivos de clientes y no envía telemetría. Solo conserva en memoria el fragmento necesario de `server-status` y muestra la versión extraída; no imprime su contenido operativo. El dominio, la cabecera `Server` y algunos errores pueden aparecer en la salida: revisa y anonimiza cualquier resultado antes de compartirlo. No habilites ni publiques `server-status` para utilizar esta herramienta.

Según el [aviso oficial de Apache](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-119618), el rango upstream afectado es 2.4.55–2.4.70 y la corrección se incluye en 2.4.71. Las distribuciones pueden incorporar módulos y correcciones en versiones distintas: consulta siempre su aviso de seguridad.
