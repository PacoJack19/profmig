#pragma once
#include <windows.h>

namespace pm {

// Abre la interfaz grafica (bucle de mensajes). Si no se esta elevado, se relanza como administrador.
int run_gui(HINSTANCE inst);

}  // namespace pm
