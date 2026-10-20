#pragma once
#include <windows.h>

namespace pm {

// UCPD (User Choice Protection Driver): controlador de Windows que impide modificar, incluso a administradores, las
// claves UserChoice de http, https y .pdf. profmig necesita borrarlas tras cambiar el SID de un perfil.
//
// Desactivar el servicio solo surte efecto tras REINICIAR. El flujo es en dos fases:
//   1) ucpd_disable(): guarda el estado original, desactiva el servicio y su tarea programada; hay que reiniciar.
//   2) tras reiniciar se ejecuta la migracion/reparacion y, al terminar con exito, ucpd_restore() lo deja como estaba
//      (volvera a estar activo en el siguiente arranque).
struct UcpdInfo {
    bool present = false;       // existe el servicio UCPD en este Windows
    bool running = false;       // el controlador esta cargado ahora mismo
    DWORD start_type = 0;       // SERVICE_SYSTEM_START (1), SERVICE_DISABLED (4)...
    bool task_known = false;    // se pudo leer la tarea programada "UCPD velocity"
    bool task_enabled = true;
};

UcpdInfo ucpd_query();

// true si profmig lo desactivo y aun no lo ha restaurado (existe el archivo de estado).
bool ucpd_disabled_by_profmig();

// Requiere administrador. Lanza Fail si no se puede cambiar el servicio. No hace nada si ya lo desactivo profmig.
void ucpd_disable();

// Restaura el estado guardado (servicio y tarea). Devuelve true si habia algo que restaurar.
// Lanza Fail si no se pudo restaurar (el archivo de estado se conserva para reintentar).
bool ucpd_restore();

}  // namespace pm
