#pragma once
#include <string>

namespace pm {

// Empaqueta una carpeta de perfil en un .zip (con el tar.exe de Windows). Omite junctions/enlaces
// simbolicos (el tar los seguiria y duplicaria datos) y cachés desechables. Lanza Fail si algo falla.
void export_profile(const std::wstring& dir, const std::wstring& zip);

// Extrae el .zip en `dest` (que no debe existir). Si falla, elimina lo que haya extraido.
void extract_profile(const std::wstring& zip, const std::wstring& dest);

}  // namespace pm
