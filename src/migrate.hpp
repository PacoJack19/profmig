#pragma once
#include <functional>
#include <string>

namespace pm {

struct Options {
    std::string command;
    std::string profile;  // ruta o usuario del perfil local
    std::string domain, dc, admin, password, user, ou, hostname;
    std::string import_zip;  // si no esta vacio: importar este .zip como perfil (en lugar de --profile)
    std::string out;         // export: ruta del .zip de salida
    std::string from_sid, to_sid;  // fixsid
    bool register_profile = false; // fixsid: registrar la carpeta en ProfileList para to_sid
    bool join = true, backup = true, creds = true, ost = true, m365 = true, icons = true, policies = true, shell = true, runonce = false;
    bool net_hygiene = true, default_logon = true;
    bool purge_gpo = false, restore_point = false, bitlocker = false, add_admin = false;
    bool dry = false, yes = false, reboot = false;
};

// Pregunta de confirmacion (solo CLI). Devuelve true para continuar. Puede ser nula.
using Confirm = std::function<bool(const std::string& resumen)>;

// Ejecuta la migracion completa. Devuelve 0 si todo fue bien. Lanza Fail ante errores de validacion
// previos a cualquier cambio; los errores posteriores hacen rollback y devuelven 1.
int run_migration(Options o, const Confirm& confirm);

// Exporta un perfil local (no cargado) a un .zip para llevarlo a otro equipo. `profile` = usuario o ruta.
int run_export(const std::string& profile, const std::string& zip);

// Deshace la ultima migracion registrada en el diario: restaura ProfileList/ProfileGuid y devuelve la
// propiedad y los permisos de la carpeta al SID original. No restaura credenciales borradas ni la union al dominio.
int run_undo(const Confirm& confirm);

// Repara una carpeta de perfil ya migrada (p. ej. con una version anterior de profmig): traduce `from` -> `to`
// en permisos NTFS y en los hives. Con register_profile registra ademas la carpeta como perfil de `to`.
int run_fixsid(const std::string& folder, const std::string& from, const std::string& to, bool register_profile);

// Utilidades compartidas con la GUI
std::string bare_user(const std::string& u);
std::string netbios_of(const std::string& domain);

}  // namespace pm
