# Checker Outlook — NIGHT CREW

Comprueba si la versión instalada de **Outlook clásico para Windows**, mediante Click-to-Run, cumple los umbrales de actualización de **CVE-2026-124194**. Lee el inventario local de Office y comprueba que existe `OUTLOOK.EXE`. No abre Outlook ni mensajes y no modifica el registro ni instala actualizaciones.

## Uso en el equipo Windows

Descarga [checker-outlook.ps1](checker-outlook.ps1), revisa su contenido y ejecútalo desde PowerShell 5.1 o posterior:

```powershell
.\checker-outlook.ps1
```

También puedes descargarlo desde PowerShell:

```powershell
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/NIGHTCREW-CL/CTI/main/tools/checker-outlook/checker-outlook.ps1' -OutFile '.\checker-outlook.ps1'
Get-Content -LiteralPath '.\checker-outlook.ps1'
.\checker-outlook.ps1
```

La descarga requiere Internet; la comprobación funciona localmente. Usa la política de ejecución aprobada por tu organización. Normalmente basta una sesión de usuario con permiso de lectura sobre las claves de Office. Este checker se ejecuta en Windows; para Apache en Linux utiliza el [checker HTTP](../checker-http/README.md).

## Resultados

| Salida | Interpretación |
| :--- | :--- |
| `VULNERABLE CVE-2026-124194` | Versión inferior al umbral de su edición, rama y canal cubiertos. Actualizar y volver a comprobar. Es una detección por versión, sin ejecutar el exploit. |
| `NOT VULNERABLE CVE-2026-124194` | La versión del inventario cumple el umbral cubierto. Se refiere únicamente a este CVE; no certifica la seguridad general de Outlook. |
| `UNKNOWN ... DEBUG=...` | No hay evidencia suficiente o la combinación no está cubierta. Requiere revisión manual; no significa protegido. |

Los resultados son texto en consola; no se definen códigos de salida específicos para automatización. Un proceso terminado con código 0 no significa que Office esté actualizado.

## Cobertura y versiones de referencia

Umbrales publicados por Microsoft el **10 de noviembre de 2026**, contrastados el **13 de noviembre de 2026**:

| Edición / canal | Versión mínima en la rama cubierta |
| :--- | :--- |
| Office LTSC 2024 Volume | `16.0.17932.21140` |
| Office LTSC 2021 Volume | `16.0.14334.21048` |
| Microsoft 365 — Current Channel | `16.0.20527.20196` |
| Microsoft 365 — Monthly Enterprise | `16.0.20527.20194`, `16.0.20430.20264` o `16.0.20326.20320`, según rama |
| Microsoft 365 — Semi-Annual Enterprise | `16.0.20527.20192`, `16.0.20430.20262` o `16.0.20326.20318`, según rama |
| Office 2021 / 2024 Retail | `16.0.20527.20196` |

Si falta el canal de Microsoft 365, se comparan los umbrales mínimo y máximo de los canales cubiertos para la misma rama: una versión intermedia devuelve `UNKNOWN`. Un canal explícito desconocido, una rama distinta o varias familias de Office cubiertas en el inventario también devuelven `UNKNOWN`.

No cubre el nuevo Outlook, Outlook web, macOS, instalaciones MSI, Office 2016/2019, canales Preview/Beta ni otras ramas de compilación. No determina si hubo explotación. Tras actualizar, cierra y vuelve a abrir Outlook según el procedimiento de tu organización; el inventario no demuestra qué binario utiliza un proceso que ya estaba abierto.

Los códigos de diagnóstico distinguen inventario ausente (`SIN_INVENTARIO_C2R`), datos inválidos (`METADATOS_INVALIDOS`), ejecutable no confirmado (`OUTLOOK_CLASSIC_NO_CONFIRMADO`) y combinaciones no cubiertas (`EDICION_*`, `RAMA_*`, `CANAL_*`). Los errores inesperados se muestran como `ERROR_LECTURA_LOCAL`, sin revelar su contenido.

## Privacidad y fuentes

El script no lee correos, contraseñas ni tokens, no incluye datos de clientes y no muestra rutas ni URLs del canal. Solo acepta rutas locales con letra de unidad para comprobar el ejecutable; no consulta rutas UNC. No realiza solicitudes HTTP ni incorpora telemetría.

- [Microsoft Security Response Center: CVE-2026-124194](https://msrc.microsoft.com/security-guidance/advisory/CVE-2026-124194).
- [Microsoft: actualizaciones de seguridad de Office](https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates).
- [Microsoft: inventario de la versión instalada mediante OfficePackageVersion](https://learn.microsoft.com/en-us/microsoft-365-apps/updates/microsoft-guidance-on-office-build-install).
- [Microsoft: identificadores de canales](https://learn.microsoft.com/es-es/intune/configmgr/sum/deploy-use/manage-office-365-proplus-updates).
