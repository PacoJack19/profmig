// profmig - migracion in-situ de perfiles de Windows a un dominio nuevo (sin copiar datos).
// Sin argumentos abre la interfaz grafica; con argumentos funciona como CLI.
#include "util.hpp"
// clang-format off
#include <shellapi.h>
// clang-format on

#include <cstdio>
#include <cstdlib>
#include <map>
#include <vector>

#include "gui.hpp"
#include "migrate.hpp"
#include "sid.hpp"
#include "ucpd.hpp"

using namespace pm;

namespace {

const wchar_t* kLogFile = L"C:\\ProfMig\\profmig.log";

void usage() {
    std::puts(
        "profmig - migracion in-situ de perfiles a un dominio nuevo\n"
        "\n"
        "Uso:\n"
        "  profmig                      Abre la interfaz grafica\n"
        "  profmig list\n"
        "  profmig export --profile <usuario|ruta> --out <archivo.zip>\n"
        "  profmig import --zip <archivo.zip> --domain <dominio> --dc <host> --admin <cuenta> --user <destino> [opciones]\n"
        "  profmig undo                 Deshace la ultima migracion (diario en C:\\ProfMig\\journal)\n"
        "  profmig ucpd status|disable|restore\n"
        "                               UCPD (proteccion de asociaciones de Windows) impide borrar las claves UserChoice.\n"
        "                               'disable' lo desactiva (requiere administrador y reiniciar); la migracion o la\n"
        "                               reparacion lo restauran solas al terminar; 'restore' lo restaura a mano\n"
        "  profmig fixsid --profile <carpeta> [--from <SID viejo>] [--to <SID nuevo>] [--register]\n"
        "                               Repara un perfil ya migrado traduciendo el SID en permisos y registro y\n"
        "                               borrando las claves UserChoice. Sin --from/--to se detectan solos\n"
        "  profmig migrate --profile <usuario|ruta> --domain <dominio> --dc <host> --admin <cuenta> --user <destino> [opciones]\n"
        "\n"
        "Obligatorios (migrate):\n"
        "  --profile X          Perfil local a migrar (nombre de usuario o ruta de la carpeta)\n"
        "  --domain X           Dominio destino (ej. empresa.local)\n"
        "  --dc X               Controlador de dominio (host o IP)\n"
        "  --admin X            Cuenta con permiso para unir equipos / consultar el dominio\n"
        "  --user X             Usuario destino (sAMAccountName, DOM\\user o user@dominio)\n"
        "\n"
        "Contrasena: --password X, o variable PROFMIG_PASSWORD, o se pide por consola (recomendado).\n"
        "\n"
        "Opciones:\n"
        "  --ou X               DN de la OU donde crear la cuenta de equipo\n"
        "  --no-join            No unir el equipo al dominio (ya esta unido)\n"
        "  --no-backup          No exportar ProfileList/ProfileGuid (sin rollback de registro)\n"
        "  --no-clean-creds     Conservar Credential Manager / Vault\n"
        "  --no-clean-ost       No archivar los .ost de Outlook\n"
        "  --no-clean-m365      No borrar tokens de Office / Entra ID\n"
        "  --no-clean-icons     No borrar los cachés de iconos y miniaturas\n"
        "  --no-clean-policies  Conservar las directivas de usuario del dominio anterior (fondo, restricciones...)\n"
        "  --no-shell-folders   No normalizar User Shell Folders\n"
        "  --runonce            Inyectar una tarea de primer inicio que re-registra las apps AppX (experimental,\n"
        "                       desactivada por defecto: puede hacer parpadear los iconos durante unos minutos)\n"
        "  --no-default-logon   No preseleccionar el usuario en la pantalla de inicio\n"
        "  --no-net-hygiene     No purgar Kerberos / DNS\n"
        "  --purge-local-gpo    Borrar la directiva de grupo LOCAL de la maquina (afecta a todo el equipo)\n"
        "  --restore-point      Crear punto de restauracion antes de empezar\n"
        "  --suspend-bitlocker  Suspender BitLocker en C: durante 1 reinicio\n"
        "  --add-admin          Anadir el usuario destino a Administradores locales\n"
        "  --dry-run            Validar y mostrar el plan sin modificar nada\n"
        "  --yes                No pedir confirmacion\n"
        "  --reboot             Reiniciar al terminar con exito\n");
}

bool parse(const std::vector<std::string>& a, Options& o) {
    if (a.size() < 2) return false;
    o.command = a[1];
    static const std::map<std::string, std::string Options::*> values = {
        {"--profile", &Options::profile}, {"--domain", &Options::domain}, {"--dc", &Options::dc},
        {"--admin", &Options::admin},     {"--password", &Options::password}, {"--user", &Options::user},
        {"--ou", &Options::ou},           {"--hostname", &Options::hostname},
        {"--out", &Options::out},         {"--zip", &Options::import_zip},
        {"--from", &Options::from_sid},   {"--to", &Options::to_sid}};
    static const std::map<std::string, std::pair<bool Options::*, bool>> flags = {
        {"--no-join", {&Options::join, false}},          {"--no-backup", {&Options::backup, false}},
        {"--no-clean-creds", {&Options::creds, false}},  {"--no-clean-ost", {&Options::ost, false}},
        {"--no-clean-m365", {&Options::m365, false}},    {"--no-clean-icons", {&Options::icons, false}},  {"--no-clean-policies", {&Options::policies, false}},    {"--no-shell-folders", {&Options::shell, false}},
        {"--no-runonce", {&Options::runonce, false}},    {"--runonce", {&Options::runonce, true}},    {"--no-default-logon", {&Options::default_logon, false}},
        {"--no-net-hygiene", {&Options::net_hygiene, false}},
        {"--purge-local-gpo", {&Options::purge_gpo, true}}, {"--restore-point", {&Options::restore_point, true}},
        {"--suspend-bitlocker", {&Options::bitlocker, true}}, {"--add-admin", {&Options::add_admin, true}},
        {"--dry-run", {&Options::dry, true}},            {"--yes", {&Options::yes, true}},
        {"--reboot", {&Options::reboot, true}}, {"--register", {&Options::register_profile, true}}};
    for (size_t i = 2; i < a.size(); ++i) {
        if (auto v = values.find(a[i]); v != values.end()) {
            if (i + 1 >= a.size()) {
                warn("Falta el valor de " + a[i]);
                return false;
            }
            o.*(v->second) = a[++i];
        } else if (auto f = flags.find(a[i]); f != flags.end()) {
            o.*(f->second.first) = f->second.second;
        } else {
            warn("Opcion desconocida: " + a[i]);
            return false;
        }
    }
    return true;
}

int cmd_list() {
    auto profiles = list_profiles();
    std::printf("%-28s %-48s %-8s %s\n", "CUENTA", "SID", "ESTADO", "RUTA");
    for (auto& p : profiles) {
        const char* st = p.loaded ? "CARGADO" : (p.exists ? "OK" : "SIN-RUTA");
        std::printf("%-28s %-48s %-8s %s\n", p.account.c_str(), p.sid.c_str(), st, narrow(p.path).c_str());
    }
    return 0;
}

int cmd_ucpd(const std::string& action) {
    try {
        if (action == "status") {
            UcpdInfo u = ucpd_query();
            if (!u.present) {
                std::puts("UCPD: no existe en este Windows (nada que hacer).");
                return 0;
            }
            std::printf("UCPD: servicio %s, tipo de inicio %lu (1=sistema, 4=desactivado), tarea 'UCPD velocity': %s\n",
                        u.running ? "ACTIVO (cargado)" : "parado", (unsigned long)u.start_type,
                        !u.task_known ? "desconocida" : (u.task_enabled ? "activada" : "desactivada"));
            std::printf("Desactivado por profmig (pendiente de restaurar): %s\n", ucpd_disabled_by_profmig() ? "SI" : "no");
            return 0;
        }
        if (action == "disable") {
            ucpd_disable();
            std::puts("Reinicia el equipo para que surta efecto y despues ejecuta la migracion o la reparacion.");
            return 0;
        }
        if (action == "restore") {
            if (!ucpd_restore()) std::puts("No hay nada que restaurar: profmig no desactivo UCPD.");
            return 0;
        }
        warn("Uso: profmig ucpd status|disable|restore");
        return 2;
    } catch (const std::exception& e) {
        warn(std::string("ERROR: ") + e.what());
        return 1;
    }
}

int cmd_migrate(Options o) {
    if (o.password.empty()) {
        if (const char* e = std::getenv("PROFMIG_PASSWORD")) o.password = e;
        else o.password = read_secret("Contrasena de " + o.admin + ": ");
    }
    Confirm confirm = [](const std::string& resumen) {
        std::printf("\n%s\nEscribe SI para continuar: ", resumen.c_str());
        std::fflush(stdout);
        char line[16] = {};
        return std::fgets(line, sizeof line, stdin) && std::string(line).find("SI") == 0;
    };
    try {
        return run_migration(o, confirm);
    } catch (const std::exception& e) {
        warn(std::string("ERROR: ") + e.what());
        return 1;
    }
}

// La aplicacion es de subsistema Windows (para que la GUI no abra consola). Para el modo CLI nos
// conectamos a la consola del proceso padre si la salida estandar no esta redirigida.
void attach_console() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out && out != INVALID_HANDLE_VALUE) return;  // redirigida a pipe/archivo
    if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) {
        std::freopen("CONOUT$", "w", stdout);
        std::freopen("CONOUT$", "w", stderr);
        std::freopen("CONIN$", "r", stdin);
    }
}

}  // namespace

int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPSTR, int) {
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) args.push_back(narrow(wargv[i]));
    LocalFree(wargv);

    log_open(kLogFile);
    if (args.size() < 2) return run_gui(inst);

    attach_console();
    SetConsoleOutputCP(CP_UTF8);

    if (args[1] == "version" || args[1] == "--version") {
        std::printf("profmig %s\n", PROFMIG_VERSION);
        return 0;
    }
    if (args[1] == "ucpd") return cmd_ucpd(args.size() > 2 ? args[2] : "status");

    Options o;
    if (!parse(args, o) || o.command == "help" || o.command == "--help") {
        usage();
        return o.command == "help" || o.command == "--help" ? 0 : 2;
    }
    if (o.command == "list") return cmd_list();
    if (o.command == "fixsid") {
        try {
            return run_fixsid(o.profile, o.from_sid, o.to_sid, o.register_profile);
        } catch (const std::exception& e) {
            warn(std::string("ERROR: ") + e.what());
            return 1;
        }
    }
    if (o.command == "export") {
        try {
            return run_export(o.profile, o.out);
        } catch (const std::exception& e) {
            warn(std::string("ERROR: ") + e.what());
            return 1;
        }
    }
    if (o.command == "undo") {
        Confirm confirm = [&o](const std::string& resumen) {
            if (o.yes) return true;
            std::printf("\n%s\nEscribe SI para continuar: ", resumen.c_str());
            std::fflush(stdout);
            char line[16] = {};
            return std::fgets(line, sizeof line, stdin) && std::string(line).find("SI") == 0;
        };
        try {
            return run_undo(confirm);
        } catch (const std::exception& e) {
            warn(std::string("ERROR: ") + e.what());
            return 1;
        }
    }
    if (o.command == "import") {
        if (o.import_zip.empty() || o.domain.empty() || o.dc.empty() || o.admin.empty() || o.user.empty()) {
            warn("Faltan parametros obligatorios.");
            usage();
            return 2;
        }
        return cmd_migrate(o);
    }
    if (o.command == "migrate") {
        if (o.profile.empty() || o.domain.empty() || o.dc.empty() || o.admin.empty() || o.user.empty()) {
            warn("Faltan parametros obligatorios.");
            usage();
            return 2;
        }
        return cmd_migrate(o);
    }
    warn("Comando desconocido: " + o.command);
    usage();
    return 2;
}
