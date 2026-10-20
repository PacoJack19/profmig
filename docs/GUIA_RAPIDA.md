# profmig — Guía rápida

Migra el perfil de un usuario de Windows a una cuenta de un dominio nuevo **sin copiar datos** (el perfil se queda en su
carpeta y se reasigna al SID del usuario nuevo). Es un único `profmig.exe`, sin instalación ni dependencias.

## Requisitos

- Windows 10 u 11 de 64 bits.
- Ejecutarlo con una **cuenta de administrador local**. La interfaz se relanza elevada sola (aviso de Windows); desde la
  consola hay que abrirla «como administrador».
- El **usuario destino ya existe** en el dominio nuevo, y tienes una cuenta de ese dominio con permiso para unir equipos.
- El DNS del equipo resuelve el dominio nuevo (si «Detectar DC» no lo encuentra, apunta el DNS al controlador).
- El usuario cuyo perfil se migra **no tiene la sesión iniciada** (usa otra cuenta de administrador).

## Contenido del paquete

| Archivo | Para qué |
|---|---|
| `profmig.exe` | El programa (interfaz gráfica sin argumentos; consola con argumentos). |
| `GUIA_RAPIDA.md` | Esta guía. |
| `README.md` | Documentación técnica completa. |
| `SHA256SUMS.txt` | Sumas de verificación (ver «Comprobar la integridad»). |
| `tools\` | Scripts de diagnóstico de solo lectura (ver «Si algo falla»). |

## Migrar un perfil (interfaz)

1. Abre `profmig.exe` y acepta el aviso de administrador.
2. Selecciona el perfil local en la lista (el botón **Calcular tamaños** es opcional).
3. Escribe el **dominio** y pulsa **Detectar DC**; rellena administrador y contraseña.
4. **Buscar en AD**: elige el usuario destino y comprueba que sale **Activa**.
5. Deja marcadas las opciones recomendadas. Pulsa **Simular (sin cambios)** y revisa el registro de abajo.
6. Pulsa **Migrar perfil**. Si Windows tiene **UCPD** activo, la herramienta te lo dirá (ver siguiente apartado).
7. Al terminar, **reinicia** e inicia sesión como `DOMINIO\usuario`. El registro debe decir `VERIFICACION CORRECTA`.

## UCPD (protección de asociaciones de Windows)

Con UCPD activo no se pueden borrar las asociaciones inválidas de `http`, `https` y `.pdf`, y el usuario migrado sufre
iconos que parpadean. Por eso `profmig` te ofrece **desactivarlo temporalmente**:

1. Al migrar o reparar, si UCPD está cargado, responde **Sí** a la pregunta. La herramienta guarda el estado original
   en `C:\ProfMig\ucpd_state.txt`, desactiva UCPD y ofrece reiniciar. **La operación no continúa en ese momento.**
2. **Reinicia** y vuelve a ejecutar la migración o la reparación.
3. Al **terminar con éxito**, `profmig` restaura UCPD como estaba (se reactiva en el siguiente arranque).

Si algo falla a mitad, UCPD no se restaura solo: `profmig ucpd restore` (consola) o aceptar la pregunta al cerrar la
interfaz. Estado actual: `profmig ucpd status`.

## Reparar un perfil ya migrado

Sirve para perfiles migrados con versiones anteriores de profmig o con otras herramientas (p. ej. ProfWiz) que sufren
cierres de sesión inmediatos, escritorio negro o iconos que parpadean.

- **Interfaz:** selecciona el perfil en la lista (con su usuario sin sesión) y pulsa **Reparar seleccionado**.
- **Consola:** `profmig fixsid --profile C:\Users\<carpeta>`

El SID anterior y el actual se detectan solos. Debe acabar con `0 con error` y `VERIFICACION CORRECTA`.

## Otras funciones

- **Exportar a .zip / Importar .zip:** mover un perfil a otro equipo.
- **Deshacer última:** restaura el registro y los permisos de la última migración (necesita que se hiciera con
  «Respaldar registro»). No recupera credenciales borradas ni saca el equipo del dominio.

## Consola

```
profmig                          Abre la interfaz
profmig list                     Lista los perfiles
profmig migrate --profile <usuario|ruta> --domain <dominio> --dc <host> --admin <cuenta> --user <destino> [--dry-run]
profmig fixsid --profile <carpeta>
profmig export --profile <usuario|ruta> --out <archivo.zip>
profmig import --zip <archivo.zip> --domain ... --dc ... --admin ... --user ...
profmig undo
profmig ucpd status|disable|restore
profmig version
```

La contraseña se pide por consola sin mostrarla (o variable `PROFMIG_PASSWORD`); no la escribas con `--password`.
El programa es de subsistema Windows: en consola, añade `| Out-Host` para que PowerShell espere a que termine.

## Dónde deja sus archivos

| Ruta | Contenido |
|---|---|
| `C:\ProfMig\profmig.log` | Registro de todas las operaciones (nunca contiene contraseñas). |
| `C:\ProfMig\backups\` | Copias `.reg` de `ProfileList` y `ProfileGuid` antes de migrar. |
| `C:\ProfMig\journal\` | Diario de migraciones (lo usa «Deshacer»). |
| `C:\ProfMig\ucpd_state.txt` | Estado original de UCPD, solo mientras está desactivado por profmig. |

## Si algo falla

- **`Acceso denegado` al arrancar `profmig.exe`:** el antivirus analiza el archivo recién copiado (no está firmado).
  Espera uno o dos minutos y repite, o cópialo con otro nombre a otra carpeta.
- **«El perfil está cargado»:** cierra la sesión de ese usuario (y reinicia si hace falta) antes de migrar o reparar.
- **Parpadeo de iconos, escritorio negro, cierre de sesión inmediato:** ejecuta **Reparar seleccionado**.
- **Diagnóstico** (los scripts de `tools\` solo leen, se ejecutan con `powershell -ExecutionPolicy Bypass -File ...`
  dentro de la sesión del usuario afectado, en una PowerShell normal):
  - `diagnose_shell.ps1` — estado del Explorador, cachés de iconos y accesos del escritorio.
  - `diagnose_edge_loop.ps1` — si Edge/WebView2 provocan un bucle de avisos de asociaciones (`-Aislar` cierra Edge unos
    segundos para comprobarlo).
  - `dump_hkcu_shell.ps1` — volcado de ajustes del Explorador para comparar dos usuarios.
  - `scan_sid_refs.ps1` y `compare_profiles.ps1` — con el usuario sin sesión, buscan restos del SID anterior o comparan
    permisos con un perfil limpio.

## Limitaciones conocidas

- Los permisos NTFS no se pueden revertir; el registro sí (respaldo `.reg`).
- Las credenciales guardadas del perfil anterior (Credential Manager, contraseñas del navegador, certificados EFS) no se
  conservan: están cifradas para el usuario anterior.
- La carpeta del perfil **conserva su nombre** (p. ej. `C:\Users\prueba1`); no se renombra a `usuario.DOMINIO`.
- El equipo queda unido al dominio nuevo, pero **no** se saca del anterior (hay que borrar su cuenta de equipo allí).

## Comprobar la integridad

```powershell
Get-FileHash .\profmig.exe -Algorithm SHA256
```
El resultado debe coincidir con la línea de `profmig.exe` en `SHA256SUMS.txt`.
