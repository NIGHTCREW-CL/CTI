# Verificación local de Apache y HTTP/2 en Linux

Estos comandos ayudan al administrador a revisar **CVE-2026-119618** desde la consola de su servidor. Son consultas: no cambian archivos, actualizan paquetes ni reinician servicios. Funcionan en las distribuciones habituales con las herramientas indicadas; las rutas y el gestor de paquetes pueden variar.

## 1. Identificar el sistema y la instancia de Apache

```sh
cat /etc/os-release

# Busca el controlador o binario disponible, incluidas rutas habituales.
APACHE_CTL=
for candidato in apache2ctl apachectl httpd apache2 \
  /usr/sbin/apache2ctl /usr/sbin/apachectl /usr/sbin/httpd \
  /usr/sbin/apache2 /usr/local/apache2/bin/apachectl; do
  if command -v "$candidato" >/dev/null 2>&1; then
    APACHE_CTL=$(command -v "$candidato")
    break
  fi
done

if [ -n "$APACHE_CTL" ]; then
  printf 'Ejecutable: %s\n' "$APACHE_CTL"
  "$APACHE_CTL" -v
  "$APACHE_CTL" -V
else
  printf '%s\n' 'Apache no encontrado: revisar ruta, contenedor o instalación personalizada.'
fi
```

Continúa en la misma terminal. Si Apache está en un contenedor, ejecuta las consultas dentro de ese contenedor. Si hay varias instalaciones, usa el ejecutable y la configuración de la instancia que atiende el sitio; el primero encontrado puede corresponder a otra instalación.

## 2. Consultar módulos y configuración

Con `APACHE_CTL` definido en el paso anterior:

```sh
if [ -n "$APACHE_CTL" ]; then
  # Módulos de la configuración actual: buscar http2_module.
  sudo "$APACHE_CTL" -M

  # Virtual hosts y archivos de configuración correspondientes.
  sudo "$APACHE_CTL" -S

  # Comprobar sintaxis y listar archivos incluidos.
  sudo "$APACHE_CTL" -t -D DUMP_INCLUDES
fi
```

Si ya eres root, puedes omitir `sudo`. Conserva los errores: una consulta fallida no demuestra que HTTP/2 esté desactivado. `-M` lee la configuración en disco; puede diferir del proceso en ejecución si hubo cambios sin recargar.

Busca las directivas relacionadas en las rutas habituales:

```sh
for directorio in /etc/apache2 /etc/httpd /usr/local/apache2/conf; do
  if [ -d "$directorio" ]; then
    sudo find "$directorio" -type f -name '*.conf' \
      -exec grep -nHE '^[[:space:]]*(Protocols|H2Direct|LoadModule[[:space:]]+http2_module)([[:space:]]|$)' {} +
  fi
done
```

`Protocols h2 http/1.1` permite HTTP/2 con TLS; `h2c` permite HTTP/2 sin TLS. Revisa la configuración global y la del virtual host correspondiente. La búsqueda también puede mostrar archivos deshabilitados: contrasta sus rutas con los archivos incluidos y con `-S`. Si no hay coincidencias, revisa instalaciones personalizadas e inclusiones sin extensión `.conf`; ese resultado no descarta por sí solo HTTP/2.

## 3. Consultar la revisión del paquete

El siguiente bloque elige el gestor disponible:

```sh
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${binary:Package}\t${Version}\n' \
    apache2 apache2-bin libapache2-mod-http2
elif command -v rpm >/dev/null 2>&1; then
  rpm -q httpd apache2 mod_http2 apache2-mod_http2
elif command -v apk >/dev/null 2>&1; then
  apk info -v apache2 apache2-http2
elif command -v pacman >/dev/null 2>&1; then
  pacman -Q apache
else
  printf '%s\n' 'Consultar el inventario o la procedencia de la compilación de Apache y mod_http2.'
fi
```

Es normal que algunos nombres no estén instalados: varían entre distribuciones y el módulo puede venir dentro del paquete principal. Compara la **revisión completa** del paquete y la versión del sistema con el aviso de su fabricante, no solo con `Apache/2.4.x`.

Por ejemplo, Ubuntu documenta que incorporó versiones nuevas del módulo en ramas antiguas de Apache; una versión inferior a 2.4.55 tampoco permite descartar el CVE. Del mismo modo, un paquete que mantiene una versión base dentro del rango puede tener la corrección aplicada.

## 4. Comprobar la negociación TLS de la instancia local

Con OpenSSL instalado, sustituye el dominio y la dirección por los de tu virtual host:

```sh
DOMINIO=example.com
DIRECCION=127.0.0.1:443
openssl s_client -connect "$DIRECCION" -servername "$DOMINIO" \
  -alpn 'h2,http/1.1' </dev/null
```

`ALPN protocol: h2` indica negociación HTTP/2 en ese listener. Esta consulta solo realiza el handshake TLS y no comprueba `h2c`. Si el servicio escucha en otra IP o puerto, cambia `DIRECCION`. Un fallo de conexión, ausencia de ALPN o un certificado distinto exige revisar el listener y el virtual host; no demuestra que todos los sitios de la instancia estén protegidos.

## Qué hacer con el resultado

Si el paquete está afectado y el servicio permite HTTP/2, aplica la actualización oficial del fabricante mediante el procedimiento de cambios de tu organización. Apache corrigió la rama upstream en **2.4.71**. Comprueba después que la instancia en ejecución usa los paquetes actualizados. Revisa también el origen y los contenedores cuando exista un proxy delante.

La versión, el módulo cargado y la negociación son evidencias complementarias; la confirmación del parche depende del aviso y la revisión del paquete. Mantén las salidas para uso interno: pueden contener nombres, rutas e IP de la infraestructura.

Fuentes oficiales, consultadas el 13 de noviembre de 2026:

- [Apache: CVE-2026-119618](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-119618).
- [Apache: opciones de httpd](https://httpd.apache.org/docs/2.4/programs/httpd.html).
- [Apache: directiva Protocols](https://httpd.apache.org/docs/2.4/mod/core.html#protocols).
- [Ubuntu: estado y revisiones corregidas](https://ubuntu.com/security/CVE-2026-119618).
- [Debian: estado por distribución](https://security-tracker.debian.org/tracker/CVE-2026-119618).
- [Red Hat: estado de mod_http2 y paquetes](https://access.redhat.com/security/cve/cve-2026-119618).
