# profmig

Migración in-situ de perfiles de Windows a un dominio nuevo (sin copiar datos). C++17, Win32 puro,
un único `.exe` estático (GUI + CLI): sin Python, sin ldap3, sin PowerShell para la lógica principal.

## Compilar

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

(MSYS2 UCRT64 `g++`, o MSVC con `cmake -S . -B build` y abrir la solución.)

## Empaquetar una versión

```
powershell -ExecutionPolicy Bypass -File package.ps1
```

Compila desde cero en Release y genera `dist\profmig-<versión>.zip` (+ `.sha256`) con `profmig.exe`, la guía rápida, este
README, los scripts de `tools\` y `SHA256SUMS.txt`. La versión sale de `project(profmig VERSION x.y.z ...)` en
`CMakeLists.txt`, y queda grabada en el `.exe` (propiedades del archivo, título de la ventana y `profmig version`).
`-Strip` quita los símbolos (exe de la mitad de tamaño); por defecto no se quitan porque algunos antivirus desconfían.

El ejecutable **no está firmado**: los antivirus (p. ej. Bitdefender) pueden retenerlo varios minutos tras copiarlo, con
«Acceso denegado» al arrancar. Para distribuirlo en producción conviene firmarlo con un certificado de firma de código.

## Interfaz gráfica

Ejecuta `profmig.exe` sin argumentos (pide elevación). Pasos: elige el perfil (con tamaño y estado), escribe el
dominio y pulsa *Detectar DC*, introduce credenciales, *Buscar en AD* (usuario/nombre/correo; avisa si la cuenta está
deshabilitada), opcionalmente *Cargar OUs*, y usa **Simular** antes de **Migrar**. El registro se ve en vivo.
Las consultas LDAP usan `wldap32` con bind Negotiate (firmado y cifrado, sin certificados).

### Mover un perfil a otro equipo (estilo Transwiz)

1. En el equipo origen: selecciona el perfil (sin sesión abierta) → **Exportar a .zip…**. Se omiten junctions
   (el `tar` las seguiría y duplicaría datos), `AppData\Local\Temp` e `INetCache`.
2. En el equipo destino (ya con el dominio configurado): rellena dominio/credenciales/usuario → **Importar .zip…**.
   Se extrae en `C:\Users\<usuario>` (o `<usuario>.<DOMINIO>` si ya existe), se registra en `ProfileList`
   y se aplica el mismo ajuste de permisos, hive y limpieza que en una migración.

### Deshacer

Cada migración deja un diario en `C:\ProfMig\journal`. **Deshacer última** quita la clave del usuario nuevo,
restaura `ProfileList`/`ProfileGuid` desde el respaldo y devuelve propiedad y permisos al SID original.
No restaura credenciales borradas ni saca el equipo del dominio. Requiere que la migración se hiciera con respaldo.
Si se deshace una importación, solo se retira el registro del perfil (la carpeta se conserva).

## Uso por línea de comandos (consola elevada)

```
profmig list
profmig export --profile juan --out D:\juan.zip
profmig import --zip D:\juan.zip --domain empresa.local --dc dc01.empresa.local --admin administrador --user juan
profmig undo
profmig migrate --profile juan --domain empresa.local --dc dc01.empresa.local --admin administrador --user juan --dry-run
profmig migrate --profile juan --domain empresa.local --dc dc01.empresa.local --admin administrador --user juan
```

La contraseña se pide por consola (o `PROFMIG_PASSWORD`); evita `--password`, que queda en el historial
de procesos. La contraseña nunca se escribe en el log (`C:\ProfMig\profmig.log`). Respaldos en `C:\ProfMig\backups`.

Siempre ejecuta primero con `--dry-run`: resuelve el SID, valida y lista el plan sin tocar nada.

## Qué hace, en orden

1. Resuelve el SID del usuario destino consultando al DC (sesión `IPC$` + `LookupAccountName`) y comprueba por LDAP si la cuenta está activa.
2. Valida: perfil existe, ni origen ni destino cargados, SID distintos.
3. Respalda `ProfileList` y `ProfileGuid` (`.reg`).
4. Une al dominio con `NetJoinDomain` (sin salir antes del dominio viejo).
5. Crea `ProfileList\<SID nuevo>` con el valor binario `Sid` correcto y reasigna `ProfileGuid`.
6. **Traducción de SID** en todos los permisos NTFS (propietario y ACEs, también las heredadas; no sigue junctions): se
   sustituye el SID viejo por el nuevo y se conserva todo lo demás (ACEs de apps, capacidades, RESTRICTED...).
7. `NTUSER.DAT` y `UsrClass.dat`: la misma traducción de SID en **todas** las claves, una a una (los hives montados
   con `RegLoadKey` no propagan la herencia: cambiar solo la raíz deja el perfil inutilizable, ver más abajo).
   Después: User Shell Folders locales, tokens Office/Entra y directivas de usuario del dominio anterior.
   La tarea de primer inicio que re-registra las apps AppX es opcional (`--runonce`) y viene desactivada.
8. Limpieza destructiva (solo si lo anterior salió bien): `.ost` → `.ost.old`, Credentials/Vault,
   cachés de identidad (IdentityCache, OneAuth, TokenBroker), cachés de iconos y miniaturas
   (`IconCache.db`, `iconcache_*.db`, `thumbcache_*.db`: evitan iconos que parpadean o se quedan en blanco).
9. Borra la clave `ProfileList` vieja, preselecciona el usuario en Winlogon, higiene Kerberos/DNS.

Si algo falla tras tocar el registro, se revierte `ProfileList`/`ProfileGuid`. **No** se revierten las ACL NTFS
ni la limpieza de credenciales.

## Reparar un perfil migrado con una versión anterior

Las versiones anteriores solo cambiaban la ACL de la raíz del hive: más de 500 claves seguían accesibles solo para el
SID viejo y el usuario era expulsado a los pocos segundos de iniciar sesión (Winlogon, evento 4006, error 5 al arrancar
`userinit.exe`). Para repararlo, sin repetir la migración y con el usuario sin sesión:

```
profmig fixsid --profile C:\Users\usuario
```

Sin más datos, el SID nuevo se toma de `ProfileList` (el SID al que está registrada esa carpeta) y el SID anterior se detecta
en el propio registro del perfil (el propietario de cuenta más frecuente). Se pueden forzar con `--from <SID>` y `--to <SID>`.
`--register` registra la carpeta como perfil de `--to` si aún no lo estaba. En la GUI: seleccionar el perfil y pulsar
**Reparar seleccionado**.

`tools\compare_profiles.ps1` compara los permisos de un perfil migrado con uno limpio de la misma cuenta; fue lo que
permitió encontrar el fallo.

## Claves UserChoice (por qué se borran)

`...\FileExts\.pdf\UserChoice`, `...\UrlAssociations\http\UserChoice` y similares guardan el programa por defecto con un
hash ligado al SID del usuario. Tras cambiar de SID el hash es inválido y Windows protege la clave a propósito, así que
no se puede reescribir. Si se deja, Edge (y su `msedgewebview2.exe`) intentan repararla una y otra vez: cada intento avisa
al Explorador de un cambio de asociaciones (`GlobalAssocChangedCounter` sube ~4 veces por segundo), el Explorador vacía
y regenera el caché de iconos, y los iconos del escritorio y de las carpetas parpadean y se quedan en blanco.
`profmig` las elimina siempre (también con `fixsid`); Windows las crea de nuevo, bien firmadas, al volver a elegir los
programas por defecto. Cómo se detectó: `Process Monitor` con el filtro `RegSetValue` + `Path ends with
GlobalAssocChangedCounter`.

### UCPD: lo gestiona profmig (requiere administrador)

En Windows 11 reciente, el controlador **UCPD** (User Choice Protection Driver) bloquea, incluso a administradores, cualquier
cambio en las claves `UserChoice` de `http`, `https` y `.pdf`. Esas tres son justo las que Edge reintenta reparar, así que en
un equipo con UCPD activo no se pueden borrar y el usuario migrado sufre el parpadeo de iconos.

`profmig` gestiona UCPD en **dos fases**, porque desactivar el servicio solo surte efecto al **reiniciar**:

1. Al migrar, importar o reparar, si UCPD está cargado, la interfaz pregunta si desactivarlo (Sí / No / Cancelar). Con
   «Sí» guarda el estado original en `C:\ProfMig\ucpd_state.txt`, desactiva el servicio y su tarea programada
   (`UCPD velocity`) y ofrece reiniciar. La operación **no continúa** en ese momento.
2. Tras reiniciar se vuelve a ejecutar la operación. Al **terminar con éxito**, `profmig` restaura UCPD exactamente como
   estaba (volverá a estar activo en el siguiente arranque, que ya hace falta para terminar la unión al dominio).

Salvaguardas: solo actúa con permisos de administrador (la GUI se relanza elevada; la consola avisa si no lo es); el estado
original se guarda **antes** de cambiar nada; si una operación falla, UCPD no se restaura (hay que reintentar o restaurarlo
a mano); al cerrar la GUI con UCPD aún desactivado se ofrece restaurarlo.

Por consola: `profmig ucpd status|disable|restore`. Manualmente, si hiciera falta:

```powershell
# Desactivar (consola de administrador) y reiniciar
Disable-ScheduledTask -TaskPath '\Microsoft\Windows\AppxDeploymentClient\' -TaskName 'UCPD velocity'
sc.exe config UCPD start= disabled        # alternativa: Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\UCPD -Name Start -Value 4

# ...migrar o ejecutar fixsid...

# Reactivar y reiniciar
sc.exe config UCPD start= system          # alternativa: -Value 1
Enable-ScheduledTask -TaskPath '\Microsoft\Windows\AppxDeploymentClient\' -TaskName 'UCPD velocity'
```

Comprobado en un perfil real: con UCPD activo, 154 de 157 claves `UserChoice` se borraron y las tres de `http`, `https` y
`.pdf` fallaron con acceso denegado; con UCPD parado se borraron las 157.

### Verificación final

Al terminar una migración o una reparación, `profmig` vuelve a abrir los hives del perfil (`NTUSER.DAT`, `UsrClass.dat` y los
de las apps de la Tienda) y comprueba que no queda ninguna clave con un propietario de cuenta ajeno (resto del SID
anterior) ni claves `UserChoice`. Imprime `VERIFICACION CORRECTA` o avisa de qué queda y cómo corregirlo. Solo lee.

### Hives de las apps de la Tienda (Helium)

Cada app empaquetada (MSIX: Widgets, Teams, Copilot, Outlook nuevo, Fotos...) tiene su propio registro virtual en
`AppData\Local\Packages\<app>\SystemAppData\Helium\User.dat` y `UserClasses.dat`, con permisos del SID del usuario. En
Process Monitor aparece como `\REGISTRY\WC\Silo…user_sid\…`. `profmig` los traduce igual que `NTUSER.DAT` (migración y
`fixsid`; `fixsid` también los usa para detectar el SID anterior cuando otra herramienta ya tradujo el resto). Si
conservan el SID anterior, la app no puede leer ni escribir su propio registro y su WebView2 puede entrar en un bucle de
avisos de asociaciones que hace que el Explorador repinte el escritorio sin parar.

## Notas

- `--purge-local-gpo` es opcional y afecta a toda la máquina, no solo al perfil.
- Los datos protegidos con DPAPI (contraseñas del navegador) y los certificados EFS del perfil viejo no se pueden
  descifrar con el SID nuevo.
- Si LDAP no responde, el estado de la cuenta no se verifica (solo es informativo) y la migración continúa.
- `PROFMIG_PREVIEW=1` abre la GUI sin elevar, solo para ver la interfaz; migrar sigue exigiendo administrador.
