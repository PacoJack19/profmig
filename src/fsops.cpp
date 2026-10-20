#include "fsops.hpp"

#include <aclapi.h>

#include <cwctype>
#include <filesystem>
#include <vector>

#include "sid.hpp"
#include "util.hpp"

namespace fs = std::filesystem;

namespace pm {

namespace {

struct Sids {
    std::vector<BYTE> user, system, admins;
};

Sids make_sids(const std::string& new_sid) {
    return {sid_from_string(new_sid), well_known_sid(WinLocalSystemSid), well_known_sid(WinBuiltinAdministratorsSid)};
}

// DACL con control total para los tres SIDs. `inherit` define a que hijos se propaga.
PACL build_full_control_acl(const Sids& s, DWORD inherit) {
    EXPLICIT_ACCESS_W ea[3] = {};
    const std::vector<BYTE>* sids[3] = {&s.user, &s.system, &s.admins};
    for (int i = 0; i < 3; ++i) {
        ea[i].grfAccessPermissions = GENERIC_ALL;
        ea[i].grfAccessMode = GRANT_ACCESS;
        ea[i].grfInheritance = inherit;
        BuildTrusteeWithSidW(&ea[i].Trustee, (PSID)sids[i]->data());
    }
    PACL acl = nullptr;
    DWORD rc = SetEntriesInAclW(3, ea, nullptr, &acl);
    if (rc != ERROR_SUCCESS) throw Fail("SetEntriesInAcl: " + win_error(rc));
    return acl;
}

bool set_owner(const std::wstring& path, SE_OBJECT_TYPE type, PSID owner) {
    return SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), type, OWNER_SECURITY_INFORMATION, owner, nullptr,
                                 nullptr, nullptr) == ERROR_SUCCESS;
}

bool set_dacl(const std::wstring& path, SE_OBJECT_TYPE type, PACL acl, bool protect) {
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION |
                              (protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    return SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), type, si, nullptr, nullptr, acl, nullptr) ==
           ERROR_SUCCESS;
}

// Secuencia que funciona aunque el objeto sea de otro usuario:
//  1) propiedad a Administradores (SeTakeOwnership)
//  2) DACL (el propietario tiene WRITE_DAC implicito)
//  3) propiedad al usuario nuevo (SeRestore)
bool apply_security(const std::wstring& path, SE_OBJECT_TYPE type, const Sids& s, PACL acl, bool protect) {
    if (!set_owner(path, type, (PSID)s.admins.data())) return false;
    if (!set_dacl(path, type, acl, protect)) return false;
    return set_owner(path, type, (PSID)s.user.data());
}

void walk(const fs::path& dir, const Sids& s, PACL empty_acl, TreeResult& r) {
    std::error_code ec;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end;
         it.increment(ec)) {
        const fs::path& p = it->path();
        DWORD attr = GetFileAttributesW(p.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            ++r.failed;
            continue;
        }
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT) continue;  // junctions y symlinks: no se siguen

        if (apply_security(p.wstring(), SE_FILE_OBJECT, s, empty_acl, false)) {
            ++r.changed;
        } else {
            DWORD err = GetLastError();
            if (++r.failed <= 10) warn("ACL no aplicada: " + narrow(p.wstring()) + " " + win_error(err));
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY) walk(p, s, empty_acl, r);
    }
}

size_t remove_contents(const fs::path& dir) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return 0;
    size_t n = 0;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code rec;
        fs::remove_all(it->path(), rec);
        if (rec) warn("No se pudo eliminar " + narrow(it->path().wstring()) + ": " + rec.message());
        else ++n;
    }
    return n;
}

std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)std::towlower(c);
    return s;
}

}  // namespace

TreeResult reassign_tree_security(const std::wstring& root, const std::string& new_sid) {
    TreeResult r;
    Sids s = make_sids(new_sid);
    PACL root_acl = build_full_control_acl(s, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

    // DACL vacia: al ser "no protegida", el hijo conserva unicamente lo que hereda del padre
    std::vector<BYTE> empty(sizeof(ACL));
    PACL empty_acl = (PACL)empty.data();
    InitializeAcl(empty_acl, (DWORD)empty.size(), ACL_REVISION);

    if (apply_security(root, SE_FILE_OBJECT, s, root_acl, true)) {
        ++r.changed;
    } else {
        ++r.failed;
        warn("No se pudo aplicar la ACL a la raiz del perfil: " + win_error(GetLastError()));
    }
    walk(root, s, empty_acl, r);
    LocalFree(root_acl);
    return r;
}

size_t archive_outlook_ost(const std::wstring& profile) {
    fs::path dir = fs::path(profile) / L"AppData" / L"Local" / L"Microsoft" / L"Outlook";
    std::error_code ec;
    size_t n = 0;
    if (!fs::is_directory(dir, ec)) return 0;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        fs::path p = it->path();
        if (lower(p.extension().wstring()) != L".ost") continue;
        fs::path dst = p;
        dst += L".old";
        std::error_code rec;
        fs::remove(dst, rec);  // sobrescribe un .ost.old previo
        fs::rename(p, dst, rec);
        if (rec) warn("No se pudo archivar " + narrow(p.wstring()) + ": " + rec.message());
        else ++n;
    }
    return n;
}

size_t purge_credentials(const std::wstring& profile) {
    // Los blobs DPAPI/Vault del SID anterior no se pueden descifrar con el SID nuevo; dejarlos provoca
    // errores de credenciales y reintentos con contrasenas viejas (bloqueo de cuenta).
    size_t n = 0;
    for (const wchar_t* rel : {L"AppData\\Roaming\\Microsoft\\Credentials", L"AppData\\Roaming\\Microsoft\\Vault",
                               L"AppData\\Local\\Microsoft\\Credentials", L"AppData\\Local\\Microsoft\\Vault"})
        n += remove_contents(fs::path(profile) / rel);
    return n;
}

size_t purge_icon_caches(const std::wstring& profile) {
    // Los cachés de iconos y miniaturas del perfil anterior no corresponden a este equipo ni a este usuario:
    // dejarlos provoca iconos que parpadean o se quedan en blanco. Windows los regenera al iniciar sesion.
    fs::path local = fs::path(profile) / L"AppData" / L"Local";
    size_t n = 0;
    std::error_code ec;
    if (fs::remove(local / L"IconCache.db", ec)) ++n;
    fs::path explorer = local / L"Microsoft" / L"Windows" / L"Explorer";
    for (fs::directory_iterator it(explorer, ec), end; !ec && it != end; it.increment(ec)) {
        std::wstring name = lower(it->path().filename().wstring());
        if (name.rfind(L"iconcache", 0) != 0 && name.rfind(L"thumbcache", 0) != 0) continue;
        std::error_code rec;
        fs::remove_all(it->path(), rec);
        if (rec) warn("No se pudo eliminar " + narrow(it->path().wstring()) + ": " + rec.message());
        else ++n;
    }
    return n;
}

size_t purge_m365_disk_caches(const std::wstring& profile) {
    fs::path local = fs::path(profile) / L"AppData" / L"Local";
    std::vector<fs::path> targets = {local / L"Microsoft" / L"IdentityCache", local / L"Microsoft" / L"OneAuth",
                                     local / L"Microsoft" / L"TokenBroker"};
    std::error_code ec;
    for (fs::directory_iterator it(local / L"Packages", ec), end; !ec && it != end; it.increment(ec)) {
        if (lower(it->path().filename().wstring()).rfind(L"microsoft.aad.brokerplugin_", 0) == 0)
            targets.push_back(it->path() / L"AC" / L"TokenBroker");
    }
    size_t n = 0;
    for (auto& t : targets) {
        std::error_code rec;
        if (!fs::exists(t, rec)) continue;
        fs::remove_all(t, rec);
        if (rec) warn("No se pudo limpiar " + narrow(t.wstring()) + ": " + rec.message());
        else ++n;
    }
    return n;
}

}  // namespace pm
