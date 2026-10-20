#pragma once
#include <windows.h>

#include <string>
#include <vector>

namespace pm {

// Traduccion de SID: sustituye `from` por `to` en el propietario y en TODAS las ACEs (explicitas y heredadas)
// de cada objeto, sin tocar nada mas. Conserva ACEs especiales (RESTRICTED, ALL APPLICATION PACKAGES,
// capacidades de apps...), el orden y las banderas de herencia. No depende de la propagacion automatica de
// Windows, que no actualiza los hives montados con RegLoadKey.

struct SdPatch {
    std::vector<BYTE> sd;  // descriptor autorrelativo a aplicar
    DWORD info = 0;        // SECURITY_INFORMATION a aplicar (propietario y/o DACL, con su proteccion)
};

// Funcion pura (testeable). `rel` es un descriptor autorrelativo con propietario y DACL.
// Devuelve false si no hay nada que cambiar.
bool translate_sd(const std::vector<BYTE>& rel, PSID from, PSID to, SdPatch& out);

struct TranslateResult {
    size_t scanned = 0, changed = 0, failed = 0;
    size_t deleted = 0;  // claves UserChoice (hash ligado al SID viejo) eliminadas para que se recreen bien
    size_t skipped = 0;  // claves UserChoice que no se pudieron eliminar
};

// Recorre una carpeta (sin seguir junctions/enlaces) y traduce cada objeto.
TranslateResult translate_tree_files(const std::wstring& root, const std::string& from, const std::string& to);

// Recorre una clave de registro y todas sus subclaves. `hive_name` es la ruta bajo `root`
// (normalmente el nombre del hive montado en HKLM).
TranslateResult translate_tree_hive(const std::wstring& hive_name, const std::string& from, const std::string& to,
                                    HKEY root = HKEY_LOCAL_MACHINE);

// Solo borra las claves UserChoice / UserChoiceLatest del hive, sin traducir ningun permiso. Para perfiles cuyos
// permisos ya estan traducidos (p. ej. migrados con ProfWiz) pero cuyas asociaciones por defecto son invalidas.
TranslateResult delete_user_choice_keys(const std::wstring& hive_name, HKEY root = HKEY_LOCAL_MACHINE);

// Verificacion de solo lectura: tras traducir un hive, cuantas claves conservan un propietario de cuenta distinto de
// `to` (resto del SID anterior) y cuantas claves UserChoice quedan. Ambas cifras deben ser 0.
struct HiveLeftovers {
    std::string foreign_sid;  // SID anterior mas frecuente ("" si ninguno)
    size_t foreign_keys = 0;
    size_t user_choice = 0;
};
HiveLeftovers scan_hive_leftovers(const std::wstring& hive_name, const std::string& to, HKEY root = HKEY_LOCAL_MACHINE);

// SID de cuenta (S-1-5-21-...) que figura como propietario en mas claves del hive, ignorando `exclude`.
// Sirve para reparar un perfil migrado sin conocer el SID anterior. Vacio si no queda ninguno.
std::string detect_foreign_owner_sid(const std::wstring& hive_name, const std::string& exclude, HKEY root = HKEY_LOCAL_MACHINE);

// SID del usuario al que pertenece un hive (propietario de la raiz o primera ACE de un SID de cuenta).
// Vacio si no se puede determinar. Se usa al importar un perfil de otro equipo.
std::string detect_hive_user_sid(const std::wstring& hive_name, HKEY root = HKEY_LOCAL_MACHINE);

}  // namespace pm
