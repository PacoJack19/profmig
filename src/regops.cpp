#include "regops.hpp"

#include <aclapi.h>

#include <filesystem>
#include <vector>

#include "fsops.hpp"
#include "sid.hpp"
#include "util.hpp"

namespace fs = std::filesystem;

namespace pm {

namespace {

const wchar_t* kProfileList = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
const wchar_t* kProfileGuid = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileGuid";

struct Key {
    HKEY h = nullptr;
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() {
        if (h) RegCloseKey(h);
    }
    operator HKEY() const { return h; }
    HKEY* put() { return &h; }
};

void check(LONG rc, const std::string& what) {
    if (rc != ERROR_SUCCESS) throw Fail(what + ": " + win_error((DWORD)rc));
}

void set_sz(HKEY k, const wchar_t* name, const std::wstring& v, DWORD type = REG_SZ) {
    check(RegSetValueExW(k, name, 0, type, (const BYTE*)v.c_str(), (DWORD)((v.size() + 1) * sizeof(wchar_t))),
          "RegSetValueEx " + narrow(name));
}

void set_dword(HKEY k, const wchar_t* name, DWORD v) {
    check(RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof v), "RegSetValueEx " + narrow(name));
}

// Abre/crea una clave dentro del hive montado; REG_OPTION_BACKUP_RESTORE ignora las ACL (SeBackup/SeRestore).
void open_in_hive(const Hive& h, const std::wstring& sub, Key& out) {
    std::wstring path = h.name() + L"\\" + sub;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, REG_OPTION_BACKUP_RESTORE,
                              KEY_READ | KEY_WRITE, nullptr, out.put(), nullptr);
    check(rc, "Abrir HKLM\\" + narrow(path));
}

std::wstring timestamp() {
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t b[32];
    swprintf(b, 32, L"%04d%02d%02d_%02d%02d%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    return b;
}

std::wstring guid_backup_for(const std::wstring& profilelist_reg) {
    std::wstring s = profilelist_reg;
    size_t p = s.find(L"ProfileList_");
    if (p != std::wstring::npos) s.replace(p, 12, L"ProfileGuid_");
    return s;
}

}  // namespace

// ---------------------------------------------------------------- Backup / restore

std::wstring backup_profile_registry(const std::wstring& dir) {
    fs::create_directories(dir);
    std::wstring ts = timestamp();
    std::wstring list_file = dir + L"\\ProfileList_" + ts + L".reg";
    std::wstring guid_file = dir + L"\\ProfileGuid_" + ts + L".reg";

    std::string out;
    int rc = run(L"reg.exe export \"HKLM\\" + std::wstring(kProfileList) + L"\" \"" + list_file + L"\" /y", &out);
    if (rc != 0) throw Fail("No se pudo exportar ProfileList: " + out);
    ok("Respaldo de ProfileList: " + narrow(list_file));

    rc = run(L"reg.exe export \"HKLM\\" + std::wstring(kProfileGuid) + L"\" \"" + guid_file + L"\" /y", &out);
    if (rc == 0) ok("Respaldo de ProfileGuid: " + narrow(guid_file));
    else warn("ProfileGuid no exportado (puede no existir).");
    return list_file;
}

void restore_profile_registry(const std::wstring& profilelist_reg) {
    std::string out;
    if (run(L"reg.exe import \"" + profilelist_reg + L"\"", &out) == 0) ok("ProfileList restaurado.");
    else warn("Fallo restaurando ProfileList: " + out);
    std::wstring guid = guid_backup_for(profilelist_reg);
    if (GetFileAttributesW(guid.c_str()) != INVALID_FILE_ATTRIBUTES) run(L"reg.exe import \"" + guid + L"\"", &out);
}

// ---------------------------------------------------------------- ProfileList

void reassign_profile_list(const std::string& old_sid, const std::string& new_sid, const std::wstring& path) {
    std::wstring wold = widen(old_sid), wnew = widen(new_sid);
    Key list;
    check(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProfileList, 0, KEY_ALL_ACCESS, list.put()), "Abrir ProfileList");

    // Restos de un primer inicio de sesion previo del usuario destino, o de un intento anterior
    RegDeleteTreeW(list, wnew.c_str());
    RegDeleteTreeW(list, (wnew + L".bak").c_str());

    Key newk;
    check(RegCreateKeyExW(list, wnew.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, newk.put(), nullptr),
          "Crear ProfileList\\" + new_sid);

    if (!old_sid.empty()) {
        // Migracion: se heredan los valores de la clave del perfil existente
        Key oldk;
        check(RegOpenKeyExW(list, wold.c_str(), 0, KEY_READ, oldk.put()), "Abrir ProfileList\\" + old_sid);
        DWORD nvals = 0, max_name = 0, max_data = 0;
        check(RegQueryInfoKeyW(oldk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &nvals, &max_name,
                               &max_data, nullptr, nullptr),
              "RegQueryInfoKey");
        std::vector<wchar_t> name(max_name + 2);
        std::vector<BYTE> data(max_data + 2);
        for (DWORD i = 0; i < nvals; ++i) {
            DWORD nl = max_name + 1, dl = max_data, type = 0;
            if (RegEnumValueW(oldk, i, name.data(), &nl, nullptr, &type, data.data(), &dl) != ERROR_SUCCESS) continue;
            RegSetValueExW(newk, name.data(), 0, type, data.data(), dl);
        }
    } else {
        // Importacion: no hay perfil previo del que copiar
        set_dword(newk, L"Flags", 0);
        set_dword(newk, L"RefCount", 0);
    }

    set_sz(newk, L"ProfileImagePath", path, REG_EXPAND_SZ);
    set_dword(newk, L"State", 0);
    set_dword(newk, L"FullProfile", 1);
    // El valor binario 'Sid' se copio con el SID viejo: tiene que reflejar el nuevo
    auto bin = sid_from_string(new_sid);
    check(RegSetValueExW(newk, L"Sid", 0, REG_BINARY, bin.data(), (DWORD)bin.size()), "Escribir Sid");

    update_profile_guid_map(old_sid, new_sid);
}

void update_profile_guid_map(const std::string& old_sid, const std::string& new_sid) {
    Key base;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProfileGuid, 0, KEY_ALL_ACCESS, base.put()) != ERROR_SUCCESS) return;

    std::vector<std::wstring> guids;
    wchar_t buf[256];
    for (DWORD i = 0;; ++i) {
        DWORD len = 256;
        if (RegEnumKeyExW(base, i, buf, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        guids.emplace_back(buf, len);
    }

    for (auto& g : guids) {
        Key k;
        if (RegOpenKeyExW(base, g.c_str(), 0, KEY_READ | KEY_SET_VALUE, k.put()) != ERROR_SUCCESS) continue;
        wchar_t val[256];
        DWORD sz = sizeof val - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(k, L"SidString", nullptr, &type, (LPBYTE)val, &sz) != ERROR_SUCCESS) continue;
        val[sz / sizeof(wchar_t)] = L'\0';
        std::string cur = narrow(val);
        if (cur == new_sid) {
            HKEY kk = k.h;  // cerrar antes de borrar la clave
            RegCloseKey(kk);
            k.h = nullptr;
            RegDeleteTreeW(base, g.c_str());
            info("ProfileGuid huerfano " + narrow(g) + " eliminado.");
        } else if (cur == old_sid) {
            set_sz(k, L"SidString", widen(new_sid));
            info("ProfileGuid " + narrow(g) + " reasignado al SID nuevo.");
        }
    }
}

void delete_profile_key(const std::string& sid) {
    Key list;
    check(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProfileList, 0, KEY_ALL_ACCESS, list.put()), "Abrir ProfileList");
    LONG rc = RegDeleteTreeW(list, widen(sid).c_str());
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) check(rc, "Borrar ProfileList\\" + sid);
}

void set_default_logon(const std::string& domain, const std::string& user) {
    Key k;
    check(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0,
                        KEY_SET_VALUE, k.put()),
          "Abrir Winlogon");
    set_sz(k, L"DefaultDomainName", widen(domain));
    set_sz(k, L"DefaultUserName", widen(user));
}

// ---------------------------------------------------------------- Hives

Hive::Hive(const std::wstring& name, const std::wstring& file) : name_(name) {
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, name_.c_str());  // resto de una ejecucion anterior interrumpida
    LONG rc = RegLoadKeyW(HKEY_LOCAL_MACHINE, name_.c_str(), file.c_str());
    if (rc != ERROR_SUCCESS) throw Fail("No se pudo montar " + narrow(file) + ": " + win_error((DWORD)rc));
    loaded_ = true;
}

bool Hive::unload() {
    if (!loaded_) return true;
    LONG rc = ERROR_SUCCESS;
    for (int i = 0; i < 8; ++i) {
        rc = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, name_.c_str());
        if (rc == ERROR_SUCCESS) {
            loaded_ = false;
            return true;
        }
        Sleep(1000);
    }
    warn("No se pudo desmontar HKLM\\" + narrow(name_) + ": " + win_error((DWORD)rc));
    return false;
}

Hive::~Hive() { unload(); }

void hive_normalize_shell_folders(const Hive& h, const std::wstring& profile_path) {
    struct Entry {
        const wchar_t* value;
        const wchar_t* path;
        const wchar_t* dir;
    };
    // Si Folder Redirection las apuntaba a un share, el perfil local debe tener las rutas por defecto
    static const Entry entries[] = {
        {L"Desktop", L"%USERPROFILE%\\Desktop", L"Desktop"},
        {L"Personal", L"%USERPROFILE%\\Documents", L"Documents"},
        {L"Favorites", L"%USERPROFILE%\\Favorites", L"Favorites"},
        {L"My Pictures", L"%USERPROFILE%\\Pictures", L"Pictures"},
        {L"My Music", L"%USERPROFILE%\\Music", L"Music"},
        {L"My Video", L"%USERPROFILE%\\Videos", L"Videos"},
        {L"{374DE290-123F-4565-9164-39C4925E467B}", L"%USERPROFILE%\\Downloads", L"Downloads"},
        {L"AppData", L"%USERPROFILE%\\AppData\\Roaming", L"AppData\\Roaming"},
        {L"Local AppData", L"%USERPROFILE%\\AppData\\Local", L"AppData\\Local"},
    };
    Key k;
    open_in_hive(h, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", k);
    for (const auto& e : entries) {
        set_sz(k, e.value, e.path, REG_EXPAND_SZ);
        std::error_code ec;
        fs::create_directories(fs::path(profile_path) / e.dir, ec);
    }
}

void hive_purge_m365(const Hive& h) {
    for (const wchar_t* sub : {L"Software\\Microsoft\\Office\\16.0\\Common\\Identity",
                               L"Software\\Microsoft\\IdentityCRL\\UserExtendedProperties"}) {
        LONG rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, (h.name() + L"\\" + sub).c_str());
        if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND)
            warn("No se pudo borrar " + narrow(sub) + ": " + win_error((DWORD)rc));
    }
}

void hive_purge_user_policies(const Hive& h) {
    // Las directivas de grupo de usuario se escriben dentro de NTUSER.DAT y Windows no las retira al cambiar de
    // dominio: un fondo de pantalla en \\servidor\..., restricciones del Explorador, etc. siguen aplicandose.
    // Se borran para que el dominio nuevo aplique las suyas desde cero; el historial del cliente de directivas
    // tambien, para que se reprocesen.
    for (const wchar_t* sub : {L"Software\\Policies", L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
                               L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy"}) {
        LONG rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, (h.name() + L"\\" + sub).c_str());
        if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND)
            warn("No se pudo borrar " + narrow(sub) + ": " + win_error((DWORD)rc));
    }
}

void hive_inject_runonce(const Hive& h) {
    // Se ejecuta en el primer inicio de sesion del usuario migrado, sin elevacion: repara el registro
    // de apps AppX/Menu Inicio de su propio perfil y refresca las directivas del dominio nuevo.
    static const wchar_t* cmd =
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \""
        L"Get-AppxPackage | ForEach-Object { $m = Join-Path $_.InstallLocation 'AppXManifest.xml'; "
        L"if (Test-Path $m) { Add-AppxPackage -DisableDevelopmentMode -Register $m -ErrorAction SilentlyContinue } }; "
        L"gpupdate /force\"";
    Key k;
    open_in_hive(h, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", k);
    set_sz(k, L"ProfMigFinalize", cmd);
}

}  // namespace pm
