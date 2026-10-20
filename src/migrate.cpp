#include "migrate.hpp"

#include "util.hpp"
// clang-format off
#include <lm.h>
#include <winsvc.h>
// clang-format on

#include <cstdio>
#include <filesystem>
#include <functional>

#include "fsops.hpp"
#include "journal.hpp"
#include "ldap.hpp"
#include "regops.hpp"
#include "secops.hpp"
#include "sid.hpp"
#include "transfer.hpp"
#include "ucpd.hpp"

namespace pm {

namespace {

const wchar_t* kBackupDir = L"C:\\ProfMig\\backups";

std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

// Aviso previo: con UCPD cargado no se pueden borrar las claves UserChoice de http, https y .pdf y, tras migrar, Edge
// intenta repararlas sin parar (iconos que parpadean). Se puede desactivar con la GUI o con "profmig ucpd disable".
void warn_if_ucpd() {
    if (!ucpd_query().running) return;
    warn("UCPD (proteccion de aplicaciones predeterminadas de Windows) esta ACTIVO: impedira borrar las claves UserChoice de "
         "http, https y .pdf y, tras migrar, Edge hara parpadear los iconos del usuario. Desactivalo con 'profmig ucpd "
         "disable' (o con el aviso de la interfaz), reinicia y vuelve a ejecutar; profmig lo restaura al terminar.");
}

// Al terminar con exito: si fue profmig quien desactivo UCPD, lo deja como estaba.
void restore_ucpd_if_needed() {
    try {
        ucpd_restore();
    } catch (const std::exception& e) {
        warn(std::string("No se pudo restaurar UCPD: ") + e.what() + " Ejecuta 'profmig ucpd restore'.");
    }
}

void join_domain(const Options& o) {
    // NETSETUP_JOIN_DOMAIN | NETSETUP_ACCT_CREATE | NETSETUP_DOMAIN_JOIN_IF_JOINED
    // DOMAIN_JOIN_IF_JOINED permite entrar al dominio nuevo sin salir antes del viejo: no se consulta
    // al dominio anterior (evita "acceso denegado" al desunirse).
    const DWORD kJoin = 0x1, kCreate = 0x2, kIfJoined = 0x20;
    std::wstring dom = widen(o.domain);
    std::wstring account = widen(o.admin.find('\\') == std::string::npos && o.admin.find('@') == std::string::npos
                                     ? o.domain + "\\" + o.admin
                                     : o.admin);
    std::wstring pass = widen(o.password);
    std::wstring ou = widen(o.ou);
    const wchar_t* pou = ou.empty() ? nullptr : ou.c_str();

    NET_API_STATUS rc =
        NetJoinDomain(nullptr, dom.c_str(), pou, account.c_str(), pass.c_str(), kJoin | kCreate | kIfJoined);
    if (rc == 2224) {  // NERR_UserExists: la cuenta de equipo ya existe, se reutiliza
        info("La cuenta de equipo ya existe en el dominio; se reutiliza.");
        rc = NetJoinDomain(nullptr, dom.c_str(), pou, account.c_str(), pass.c_str(), kJoin | kIfJoined);
    }
    if (rc == 2691) {  // NERR_SetupAlreadyJoined
        info("El equipo ya estaba unido a " + o.domain + ".");
        return;
    }
    if (rc != 0) {
        std::string hint;
        if (rc == 5) hint = " (credenciales sin permiso para unir equipos)";
        if (rc == 1326) hint = " (usuario o contrasena incorrectos)";
        if (rc == 1355) hint = " (no se encuentra el DC: revisa el DNS)";
        throw Fail("NetJoinDomain fallo: " + win_error(rc) + hint);
    }
    ok("Equipo unido a " + o.domain + " (el reinicio queda pendiente).");
}

void add_to_local_admins(const std::string& sid_str) {
    auto admins = well_known_sid(WinBuiltinAdministratorsSid);
    wchar_t name[256], dom[256];
    DWORD nn = 256, dn = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, admins.data(), name, &nn, dom, &dn, &use))
        throw Fail("No se pudo resolver el grupo Administradores: " + win_error(GetLastError()));
    auto sid = sid_from_string(sid_str);
    LOCALGROUP_MEMBERS_INFO_0 m{};
    m.lgrmi0_sid = sid.data();
    NET_API_STATUS rc = NetLocalGroupAddMembers(nullptr, name, 0, (LPBYTE)&m, 1);
    if (rc == 0 || rc == 1378) ok("Usuario anadido a Administradores locales.");  // 1378: ya era miembro
    else warn("No se pudo anadir a Administradores: " + win_error(rc));
}

void purge_local_gpo() {
    wchar_t sysroot[MAX_PATH];
    GetEnvironmentVariableW(L"SystemRoot", sysroot, MAX_PATH);
    for (const wchar_t* d : {L"\\System32\\GroupPolicy", L"\\System32\\GroupPolicyUsers"}) {
        std::error_code ec;
        std::filesystem::remove_all(std::wstring(sysroot) + d, ec);
    }
    ok("Directivas de grupo locales eliminadas.");
}

const Profile* find_profile(const std::vector<Profile>& all, const std::string& wanted) {
    std::wstring w = lower(widen(wanted));
    for (auto& p : all) {
        std::wstring path = lower(p.path);
        std::wstring folder = path.substr(path.find_last_of(L'\\') + 1);
        std::wstring acct = lower(widen(p.account));
        std::wstring acct_short = acct.substr(acct.find_last_of(L'\\') + 1);
        if (w == path || w == folder || w == acct || w == acct_short) return &p;
    }
    return nullptr;
}

// Registro virtual de cada app empaquetada (MSIX): AppData\Local\Packages\<app>\SystemAppData\Helium\User.dat y
// UserClasses.dat. Contiene permisos con el SID del usuario, asi que tambien hay que traducirlo: si conserva el SID
// anterior, la app no puede leer ni escribir su propio HKCU virtual (p. ej. WebView2 reintenta sin parar y el
// Explorador repinta el escritorio en bucle).
std::vector<std::wstring> find_package_hives(const std::wstring& profile) {
    std::vector<std::wstring> out;
    std::error_code ec;
    std::filesystem::path packages = std::filesystem::path(profile) / L"AppData" / L"Local" / L"Packages";
    for (std::filesystem::directory_iterator it(packages, ec), end; !ec && it != end; it.increment(ec)) {
        std::filesystem::path helium = it->path() / L"SystemAppData" / L"Helium";
        for (const wchar_t* n : {L"User.dat", L"UserClasses.dat"}) {
            std::error_code e2;
            std::filesystem::path f = helium / n;
            if (std::filesystem::is_regular_file(f, e2)) out.push_back(f.wstring());
        }
    }
    return out;
}

// SID anterior que conserve alguno de los hives de paquetes ("" si ninguno).
std::string detect_from_package_hives(const std::wstring& profile, const std::string& to) {
    for (const auto& f : find_package_hives(profile)) {
        try {
            Hive h(L"ProfMigPkg", f);
            std::string s = detect_foreign_owner_sid(h.name(), to);
            h.unload();
            if (!s.empty()) return s;
        } catch (const std::exception&) {
        }
    }
    return "";
}

struct PackageHivesResult {
    size_t hives = 0, changed = 0, failed = 0, errors = 0;
};

// `from` vacio: se detecta el SID anterior de cada hive (importaciones).
PackageHivesResult translate_package_hives(const std::wstring& profile, const std::string& from, const std::string& to) {
    PackageHivesResult res;
    for (const auto& f : find_package_hives(profile)) {
        try {
            Hive h(L"ProfMigPkg", f);
            std::string src = from.empty() ? detect_hive_user_sid(h.name()) : from;
            if (!src.empty() && src != to) {
                TranslateResult r = translate_tree_hive(h.name(), src, to);
                res.changed += r.changed;
                res.failed += r.failed;
            }
            ++res.hives;
            if (!h.unload()) {
                warn("No se pudo desmontar " + narrow(f));
                ++res.errors;
            }
        } catch (const std::exception& e) {
            warn("No se pudo procesar " + narrow(f) + ": " + e.what());
            ++res.errors;
        }
    }
    return res;
}

// Verificacion final de solo lectura: vuelve a abrir los hives del perfil y comprueba que no queda ninguna clave con un
// propietario de cuenta distinto del usuario actual (resto del SID anterior) ni claves UserChoice. Solo avisa.
void verify_profile(const std::wstring& path, const std::string& to) {
    info("Verificando el perfil...");
    size_t foreign = 0, user_choice = 0, hives = 0;
    std::string sid;
    auto check = [&](const wchar_t* name, const std::wstring& file) {
        if (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES) return;
        try {
            Hive h(name, file);
            HiveLeftovers l = scan_hive_leftovers(h.name(), to);
            foreign += l.foreign_keys;
            user_choice += l.user_choice;
            if (sid.empty()) sid = l.foreign_sid;
            ++hives;
            h.unload();
        } catch (const std::exception& e) {
            warn("Verificacion: no se pudo abrir " + narrow(file) + ": " + e.what());
        }
    };
    check(L"ProfMigHive", path + L"\\NTUSER.DAT");
    check(L"ProfMigClasses", path + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat");
    for (const auto& f : find_package_hives(path)) check(L"ProfMigPkg", f);

    if (foreign == 0 && user_choice == 0) {
        ok("VERIFICACION CORRECTA: " + std::to_string(hives) + " hives revisados, sin restos del SID anterior ni claves UserChoice.");
        return;
    }
    if (foreign > 0)
        warn("VERIFICACION: " + std::to_string(foreign) + " clave(s) conservan un propietario de cuenta ajeno al usuario (p. ej. " +
             sid + "). El perfil puede dar problemas; ejecuta 'Reparar seleccionado'.");
    if (user_choice > 0)
        warn("VERIFICACION: quedan " + std::to_string(user_choice) + " clave(s) UserChoice. Si UCPD estaba activo, desactivalo, "
             "reinicia y repara el perfil; si no, Edge puede hacer parpadear los iconos.");
}

}  // namespace

std::string bare_user(const std::string& u) {
    size_t b = u.find('\\');
    if (b != std::string::npos) return u.substr(b + 1);
    size_t at = u.find('@');
    if (at != std::string::npos) return u.substr(0, at);
    return u;
}

std::string netbios_of(const std::string& domain) {
    std::string d = domain.substr(0, domain.find('.'));
    for (auto& c : d) c = (char)toupper((unsigned char)c);
    return d;
}

int run_migration(Options o, const Confirm& confirm) {
    g_dry = o.dry;
    const bool importing = !o.import_zip.empty();
    if ((o.profile.empty() && !importing) || o.domain.empty() || o.dc.empty() || o.admin.empty() || o.user.empty() ||
        o.password.empty())
        throw Fail("Faltan parametros obligatorios (perfil o .zip, dominio, DC, administrador, contrasena y usuario destino).");
    if (!is_admin()) throw Fail("Se requieren permisos de Administrador (consola/ejecucion elevada).");
    for (const wchar_t* p : {SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME})
        if (!enable_privilege(p)) warn("No se pudo habilitar el privilegio " + narrow(p));

    const std::string target = bare_user(o.user);

    // ---- 1. Validaciones (nada se modifica todavia)
    std::string old_sid, old_account;
    std::wstring path;
    if (importing) {
        if (GetFileAttributesW(widen(o.import_zip).c_str()) == INVALID_FILE_ATTRIBUTES)
            throw Fail("No existe el archivo a importar: " + o.import_zip);
        path = L"C:\\Users\\" + widen(target);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) path += L"." + widen(netbios_of(o.domain));
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
            throw Fail("Ya existe la carpeta de perfil " + narrow(path) + "; no se puede importar encima.");
        old_account = "(importado de " + o.import_zip + ")";
        info("Perfil a importar: " + o.import_zip + " -> " + narrow(path));
    } else {
        auto profiles = list_profiles();
        const Profile* prof = find_profile(profiles, o.profile);
        if (!prof) throw Fail("No se encontro el perfil '" + o.profile + "'. Usa 'profmig list'.");
        if (!prof->exists) throw Fail("La carpeta del perfil no existe: " + narrow(prof->path));
        old_sid = prof->sid;
        path = prof->path;
        old_account = prof->account;
        info("Perfil origen: " + old_account + "  " + old_sid + "  " + narrow(path));
    }

    info("Resolviendo SID de " + target + " en " + o.domain + " via " + o.dc + "...");
    const std::string new_sid = resolve_domain_sid(o.dc, o.domain, target, o.admin, o.password);
    ok("SID destino: " + new_sid);

    // Estado de la cuenta (solo informativo; si LDAP no responde se continua)
    try {
        for (auto& u : ad_find_users(o.dc, o.domain, o.admin, o.password, target, 10)) {
            if (_stricmp(u.sam.c_str(), target.c_str()) != 0) continue;
            if (!u.enabled) warn("La cuenta " + u.sam + " figura como " + u.status + " en AD: no podra iniciar sesion.");
            else ok("Cuenta en AD: " + u.sam + " (" + u.display + ") - " + u.status);
            break;
        }
    } catch (const std::exception& e) {
        info(std::string("Estado de la cuenta no verificado por LDAP: ") + e.what());
    }

    if (!importing && old_sid == new_sid) throw Fail("El perfil ya pertenece a ese usuario; no hay nada que migrar.");
    if (!importing && is_profile_loaded(old_sid))
        throw Fail("El perfil origen esta cargado (sesion abierta o procesos). Cierra la sesion y reintenta.");
    if (is_profile_loaded(new_sid))
        throw Fail("El perfil del usuario destino esta cargado. Cierra su sesion y reintenta.");

    warn_if_ucpd();
    if (g_dry) {
        info("--- MODO SIMULACION: no se modificara nada ---");
    } else if (confirm && !o.yes) {
        std::string resumen = "Se migrara " + old_account + " (" + old_sid + ") -> " + o.domain + "\\" + target +
                              " (" + new_sid + ").";
        if (!confirm(resumen)) {
            info("Cancelado.");
            return 1;
        }
    }

    // ---- 2. Ejecucion con rollback
    std::wstring backup_file;
    bool new_key_created = false;
    Journal jr;
    bool jr_written = false;
    auto step = [&](const std::string& title, const std::function<void()>& fn) {
        if (g_dry) {
            dry(title);
            return;
        }
        info(title);
        fn();
    };

    try {
        if (o.restore_point)
            step("Creando punto de restauracion", [] {
                std::string out;
                int rc = run(L"powershell.exe -NoProfile -Command \"Enable-ComputerRestore -Drive 'C:\\'; "
                             L"Checkpoint-Computer -Description 'ProfMig' -RestorePointType MODIFY_SETTINGS\"",
                             &out);
                if (rc == 0) ok("Punto de restauracion creado.");
                else warn("Punto de restauracion no disponible: " + out.substr(0, 200));
            });
        if (o.bitlocker)
            step("Suspendiendo BitLocker (1 reinicio)", [] {
                std::string out;
                if (run(L"manage-bde.exe -protectors -disable C: -RebootCount 1", &out) == 0) ok("BitLocker suspendido.");
                else warn("BitLocker no activo o no soportado.");
            });
        if (o.purge_gpo) step("Eliminando GPO local", purge_local_gpo);

        if (o.backup) step("Respaldando registro", [&] { backup_file = backup_profile_registry(kBackupDir); });
        else if (!g_dry) warn("Sin respaldo: no habra rollback de registro.");

        if (o.join) step("Uniendo al dominio " + o.domain, [&] { join_domain(o); });

        if (importing)
            step("Extrayendo el perfil en " + narrow(path), [&] { extract_profile(widen(o.import_zip), path); });

        step(importing ? "Registrando el perfil para " + new_sid
                       : "Reasignando ProfileList " + old_sid + " -> " + new_sid,
             [&] {
                 reassign_profile_list(old_sid, new_sid, path);
                 new_key_created = true;
                 jr = Journal{old_sid, new_sid, old_account, o.domain, target, path, backup_file, importing, L""};
                 try {
                     journal_write(jr);
                     jr_written = true;
                 } catch (const std::exception& e) {
                     warn(std::string("No se pudo escribir el diario (no podras usar 'Deshacer'): ") + e.what());
                 }
             });

        step("Reasignando propietario y permisos NTFS (puede tardar)", [&] {
            if (importing) {
                // Archivos recien extraidos: no tienen ACL propias que conservar
                TreeResult r = reassign_tree_security(path, new_sid);
                ok("NTFS: " + std::to_string(r.changed) + " objetos actualizados, " + std::to_string(r.failed) + " con error.");
                if (r.failed > 0) warn("Revisa los avisos anteriores; el perfil puede tener elementos sin permisos.");
            } else {
                // Traduccion de SID: se conservan las ACEs especiales (apps, capacidades, RESTRICTED...)
                TranslateResult r = translate_tree_files(path, old_sid, new_sid);
                ok("NTFS: " + std::to_string(r.scanned) + " objetos revisados, " + std::to_string(r.changed) +
                   " traducidos, " + std::to_string(r.failed) + " con error.");
                if (r.failed > 0) warn("Revisa los avisos anteriores; el perfil puede tener elementos sin permisos.");
            }
        });

        // SID que figura dentro de un hive: el viejo en una migracion, el del equipo de origen en una importacion
        auto translate_hive = [&](const Hive& h) {
            std::string from = importing ? detect_hive_user_sid(h.name()) : old_sid;
            if (from.empty()) throw Fail("No se pudo determinar a que usuario pertenece el hive " + narrow(h.name()) + ".");
            TranslateResult r = translate_tree_hive(h.name(), from, new_sid);
            ok("Registro " + narrow(h.name()) + ": " + std::to_string(r.scanned) + " claves revisadas, " +
               std::to_string(r.changed) + " traducidas, " + std::to_string(r.deleted) + " UserChoice eliminadas, " + std::to_string(r.skipped) + " omitidas, " +
               std::to_string(r.failed) + " con error.");
            if (r.skipped > 0)
                warn(std::to_string(r.skipped) + " clave(s) UserChoice (http, https, .pdf) estan protegidas por Windows (UCPD) y no se pudieron eliminar. Edge puede hacer parpadear los iconos hasta que el usuario las restablezca: Configuracion > Aplicaciones > Aplicaciones predeterminadas > Restablecer todas las aplicaciones predeterminadas.");
            if (r.failed > 0) throw Fail("No se pudieron traducir todos los permisos del registro; el perfil no iniciaria sesion.");
        };

        step("Ajustando NTUSER.DAT", [&] {
            Hive h(L"ProfMigHive", path + L"\\NTUSER.DAT");
            translate_hive(h);
            if (o.shell) {
                hive_normalize_shell_folders(h, path);
                ok("User Shell Folders normalizadas.");
            }
            if (o.m365) {
                hive_purge_m365(h);
                ok("Tokens de Office / Entra ID eliminados del hive.");
            }
            if (o.policies) {
                hive_purge_user_policies(h);
                ok("Directivas de usuario del dominio anterior eliminadas del hive.");
            }
            if (o.runonce) {
                hive_inject_runonce(h);
                ok("Tarea RunOnce programada.");
            }
            if (!h.unload()) throw Fail("No se pudo desmontar NTUSER.DAT; los cambios podrian perderse.");
        });

        std::wstring usrclass = path + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat";
        if (GetFileAttributesW(usrclass.c_str()) != INVALID_FILE_ATTRIBUTES)
            step("Ajustando UsrClass.dat", [&] {
                Hive h(L"ProfMigClasses", usrclass);
                translate_hive(h);
                if (!h.unload()) throw Fail("No se pudo desmontar UsrClass.dat.");
            });

        step("Ajustando los hives de las apps de la Tienda (Helium)", [&] {
            PackageHivesResult pr = translate_package_hives(path, importing ? std::string() : old_sid, new_sid);
            ok("Hives de apps de la Tienda: " + std::to_string(pr.hives) + " revisados, " + std::to_string(pr.changed) +
               " claves traducidas, " + std::to_string(pr.failed) + " con error, " + std::to_string(pr.errors) + " no procesados.");
            if (pr.failed > 0 || pr.errors > 0)
                warn("Algunas apps de la Tienda podrian no leer su registro privado; revisa los avisos anteriores.");
        });

        // Limpieza destructiva al final: solo si todo lo reversible ya salio bien
        if (o.ost)
            step("Archivando .ost de Outlook",
                 [&] { ok(std::to_string(archive_outlook_ost(path)) + " archivo(s) archivado(s)."); });
        if (o.creds)
            step("Purgando credenciales y Vault",
                 [&] { ok(std::to_string(purge_credentials(path)) + " elemento(s) eliminado(s)."); });
        if (o.m365)
            step("Purgando caches de identidad en disco",
                 [&] { ok(std::to_string(purge_m365_disk_caches(path)) + " ubicacion(es) limpiada(s)."); });
        if (o.icons)
            step("Limpiando caches de iconos y miniaturas",
                 [&] { ok(std::to_string(purge_icon_caches(path)) + " archivo(s) de cache eliminado(s)."); });

        step("Verificando el perfil", [&] { verify_profile(path, new_sid); });

        if (!importing) step("Retirando la clave ProfileList antigua", [&] { delete_profile_key(old_sid); });
        if (o.default_logon)
            step("Preseleccionando usuario en el inicio de sesion",
                 [&] { set_default_logon(netbios_of(o.domain), target); });
        if (o.add_admin) step("Anadiendo a Administradores locales", [&] { add_to_local_admins(new_sid); });
        if (o.net_hygiene)
            step("Purgando Kerberos y DNS", [] {
                run(L"klist.exe purge");
                run(L"ipconfig.exe /flushdns");
                run(L"ipconfig.exe /registerdns");
            });
    } catch (const std::exception& e) {
        warn(std::string("ERROR: ") + e.what());
        if (new_key_created) {
            warn("Iniciando rollback...");
            try {
                delete_profile_key(new_sid);
            } catch (...) {
            }
            if (!backup_file.empty()) restore_profile_registry(backup_file);
            if (jr_written) journal_mark_undone(jr);
            warn("Rollback del registro terminado. Los permisos NTFS y la limpieza de credenciales NO se revierten.");
        }
        return 1;
    }

    if (g_dry) {
        info("Simulacion completada: sin cambios.");
        return 0;
    }
    restore_ucpd_if_needed();
    ok("MIGRACION COMPLETADA. Reinicia e inicia sesion como " + netbios_of(o.domain) + "\\" + target);
    if (o.reboot) run(L"shutdown.exe /r /t 15 /c \"profmig: migracion completada\"");
    return 0;
}

int run_export(const std::string& profile, const std::string& zip) {
    if (profile.empty() || zip.empty()) throw Fail("Indica el perfil y la ruta del .zip de salida.");
    if (!is_admin()) throw Fail("Se requieren permisos de Administrador (consola/ejecucion elevada).");
    for (const wchar_t* p : {SE_BACKUP_NAME, SE_RESTORE_NAME}) enable_privilege(p);

    std::wstring dir;
    auto profiles = list_profiles();
    if (const Profile* p = find_profile(profiles, profile)) {
        if (p->loaded) throw Fail("El perfil esta cargado (sesion abierta). Cierra la sesion de ese usuario y reintenta.");
        if (!p->exists) throw Fail("La carpeta del perfil no existe: " + narrow(p->path));
        dir = p->path;
        info("Exportando perfil de " + p->account + " (" + narrow(dir) + ")");
    } else if (GetFileAttributesW(widen(profile).c_str()) != INVALID_FILE_ATTRIBUTES) {
        dir = widen(profile);  // carpeta arbitraria
    } else {
        throw Fail("No se encontro el perfil '" + profile + "'.");
    }
    export_profile(dir, widen(zip));
    return 0;
}

int run_fixsid(const std::string& folder, const std::string& from_in, const std::string& to_in, bool register_profile) {
    if (folder.empty()) throw Fail("Indica --profile <carpeta del perfil>.");
    if (!is_admin()) throw Fail("Se requieren permisos de Administrador (consola/ejecucion elevada).");
    for (const wchar_t* p : {SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME})
        if (!enable_privilege(p)) warn("No se pudo habilitar el privilegio " + narrow(p));

    const std::wstring path = widen(folder);
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) throw Fail("No existe la carpeta " + folder);
    if (GetFileAttributesW((path + L"\\NTUSER.DAT").c_str()) == INVALID_FILE_ATTRIBUTES)
        throw Fail("La carpeta no contiene NTUSER.DAT: no parece un perfil de Windows.");

    // SID nuevo: el que tiene registrada esa carpeta en ProfileList (salvo que se indique con --to)
    std::string to = to_in;
    if (to.empty() || to == "auto") {
        auto norm = [](std::wstring s) {
            while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
            return lower(s);
        };
        to.clear();
        for (auto& p : list_profiles())
            if (norm(p.path) == norm(path)) {
                to = p.sid;
                break;
            }
        if (to.empty()) throw Fail("Esa carpeta no figura en ProfileList; indica el SID nuevo con --to <SID>.");
        info("SID del perfil (ProfileList): " + to);
    }
    sid_from_string(to);  // valida el formato
    if (is_profile_loaded(to)) throw Fail("El perfil " + to + " esta cargado. Cierra su sesion (y reinicia si hace falta).");

    // SID anterior: el propietario de cuenta mas frecuente en el registro del perfil (salvo que se indique con --from)
    std::string from = from_in;
    bool translate = true;  // false: los permisos ya estan traducidos (p. ej. migrado con ProfWiz) y solo faltan las UserChoice
    if (from.empty() || from == "auto") {
        {
            Hive probe(L"ProfMigHive", path + L"\\NTUSER.DAT");
            from = detect_foreign_owner_sid(probe.name(), to);
            if (!probe.unload()) throw Fail("No se pudo desmontar NTUSER.DAT.");
        }
        if (from.empty()) {
            // Otra herramienta (p. ej. ProfWiz) puede haber traducido NTUSER.DAT y dejar UsrClass.dat con el SID viejo
            std::wstring uc = path + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat";
            if (GetFileAttributesW(uc.c_str()) != INVALID_FILE_ATTRIBUTES) {
                Hive probe(L"ProfMigClasses", uc);
                from = detect_foreign_owner_sid(probe.name(), to);
                if (!probe.unload()) throw Fail("No se pudo desmontar UsrClass.dat.");
                if (!from.empty()) info("NTUSER.DAT ya esta traducido, pero UsrClass.dat conserva el SID anterior.");
            }
        }
        if (from.empty()) {
            from = detect_from_package_hives(path, to);
            if (!from.empty())
                info("NTUSER.DAT y UsrClass.dat ya estan traducidos, pero los hives de las apps de la Tienda (Helium) "
                     "conservan el SID anterior.");
        }
        if (from.empty()) {
            translate = false;
            info("No se detecto ningun SID anterior en el registro: los permisos ya estan traducidos (¿migrado con ProfWiz u "
                 "otra herramienta?). Solo se eliminaran las claves UserChoice invalidas.");
        } else {
            info("SID anterior detectado en el registro: " + from);
        }
    }
    if (translate) {
        sid_from_string(from);
        if (is_profile_loaded(from)) throw Fail("El perfil " + from + " esta cargado. Cierra su sesion (y reinicia si hace falta).");
    }

    warn_if_ucpd();
    if (translate) {
        info("Reparando " + folder + ":  " + from + "  ->  " + to);
        TranslateResult r = translate_tree_files(path, from, to);
        ok("NTFS: " + std::to_string(r.scanned) + " objetos revisados, " + std::to_string(r.changed) + " traducidos, " +
           std::to_string(r.failed) + " con error.");
    } else {
        info("Reparando " + folder + " (solo claves UserChoice)");
    }

    bool hive_ok = true;
    {
        Hive h(L"ProfMigHive", path + L"\\NTUSER.DAT");
        TranslateResult hr = translate ? translate_tree_hive(h.name(), from, to) : delete_user_choice_keys(h.name());
        ok("NTUSER.DAT: " + std::to_string(hr.scanned) + " claves revisadas, " + std::to_string(hr.changed) +
           " traducidas, " + std::to_string(hr.deleted) + " UserChoice eliminadas, " + std::to_string(hr.skipped) + " omitidas, " + std::to_string(hr.failed) + " con error.");
        hive_ok = hr.failed == 0;
        if (hr.skipped > 0)
            warn(std::to_string(hr.skipped) + " clave(s) UserChoice (http, https, .pdf) estan protegidas por Windows (UCPD) y no se pudieron eliminar. Edge puede hacer parpadear los iconos hasta que el usuario las restablezca: Configuracion > Aplicaciones > Aplicaciones predeterminadas > Restablecer todas las aplicaciones predeterminadas.");
        if (!h.unload()) throw Fail("No se pudo desmontar NTUSER.DAT.");
    }
    std::wstring usrclass = path + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat";
    if (translate && GetFileAttributesW(usrclass.c_str()) != INVALID_FILE_ATTRIBUTES) {
        Hive h(L"ProfMigClasses", usrclass);
        TranslateResult hr = translate_tree_hive(h.name(), from, to);
        ok("UsrClass.dat: " + std::to_string(hr.scanned) + " claves revisadas, " + std::to_string(hr.changed) +
           " traducidas, " + std::to_string(hr.deleted) + " UserChoice eliminadas, " + std::to_string(hr.skipped) + " omitidas, " + std::to_string(hr.failed) + " con error.");
        hive_ok = hive_ok && hr.failed == 0;
        if (!h.unload()) throw Fail("No se pudo desmontar UsrClass.dat.");
    }
    if (translate) {
        PackageHivesResult pr = translate_package_hives(path, from, to);
        ok("Hives de apps de la Tienda (Helium): " + std::to_string(pr.hives) + " revisados, " + std::to_string(pr.changed) +
           " claves traducidas, " + std::to_string(pr.failed) + " con error, " + std::to_string(pr.errors) + " no procesados.");
        hive_ok = hive_ok && pr.failed == 0;
    }
    if (!hive_ok) throw Fail("No se pudieron traducir todas las claves del registro; no se registra el perfil.");
    verify_profile(path, to);

    if (register_profile) {
        info("Registrando la carpeta como perfil de " + to + " (respaldo previo del registro)");
        backup_profile_registry(kBackupDir);
        reassign_profile_list("", to, path);
        ok("Perfil registrado. El usuario ya puede iniciar sesion con esta carpeta.");
    } else {
        ok("Reparacion terminada. Usa --register para registrar la carpeta en ProfileList si aun no lo esta.");
    }
    restore_ucpd_if_needed();
    return 0;
}

int run_undo(const Confirm& confirm) {
    if (!is_admin()) throw Fail("Se requieren permisos de Administrador (consola/ejecucion elevada).");
    for (const wchar_t* p : {SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME}) enable_privilege(p);

    auto last = journal_last();
    if (!last) throw Fail("No hay ninguna migracion en el diario que se pueda deshacer.");
    Journal j = *last;
    info("Ultima migracion: " + j.account + " -> " + j.domain + "\\" + j.user + "  (" + narrow(j.path) + ")");

    if (!j.imported) {
        if (j.backup.empty() || GetFileAttributesW(j.backup.c_str()) == INVALID_FILE_ATTRIBUTES)
            throw Fail("No hay respaldo del registro de esa migracion; no se puede deshacer automaticamente.");
        if (GetFileAttributesW(j.path.c_str()) == INVALID_FILE_ATTRIBUTES)
            throw Fail("La carpeta del perfil ya no existe: " + narrow(j.path));
    }
    if (is_profile_loaded(j.new_sid))
        throw Fail("El perfil del usuario " + j.user + " esta cargado. Cierra su sesion y reintenta.");

    if (confirm) {
        std::string msg = j.imported ? "Se quitara el registro del perfil importado de " + j.user +
                                           " (la carpeta " + narrow(j.path) + " se conserva)."
                                     : "Se devolvera el perfil " + narrow(j.path) + " a " + j.account +
                                           " (SID " + j.old_sid + ").";
        if (!confirm(msg + "\nNo se restauran credenciales borradas ni se saca el equipo del dominio.")) {
            info("Cancelado.");
            return 1;
        }
    }

    try {
        info("Quitando la clave ProfileList del usuario nuevo");
        delete_profile_key(j.new_sid);

        if (!j.imported) {
            info("Restaurando ProfileList / ProfileGuid desde el respaldo");
            restore_profile_registry(j.backup);

            info("Devolviendo propietario y permisos al SID original (puede tardar)");
            TranslateResult r = translate_tree_files(j.path, j.new_sid, j.old_sid);
            ok("NTFS: " + std::to_string(r.scanned) + " objetos revisados, " + std::to_string(r.changed) +
               " traducidos, " + std::to_string(r.failed) + " con error.");

            info("Ajustando NTUSER.DAT");
            {
                Hive h(L"ProfMigHive", j.path + L"\\NTUSER.DAT");
                TranslateResult hr = translate_tree_hive(h.name(), j.new_sid, j.old_sid);
                ok("Registro: " + std::to_string(hr.changed) + " claves traducidas, " + std::to_string(hr.failed) + " con error.");
                if (!h.unload()) throw Fail("No se pudo desmontar NTUSER.DAT.");
            }
            std::wstring usrclass = j.path + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat";
            if (GetFileAttributesW(usrclass.c_str()) != INVALID_FILE_ATTRIBUTES) {
                Hive h(L"ProfMigClasses", usrclass);
                translate_tree_hive(h.name(), j.new_sid, j.old_sid);
                if (!h.unload()) throw Fail("No se pudo desmontar UsrClass.dat.");
            }
        }
        journal_mark_undone(j);
    } catch (const std::exception& e) {
        warn(std::string("ERROR deshaciendo la migracion: ") + e.what());
        return 1;
    }
    ok("Migracion deshecha.");
    return 0;
}

}  // namespace pm
