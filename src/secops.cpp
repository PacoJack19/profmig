#include "secops.hpp"

#include <aclapi.h>
#include <sddl.h>

#include <cstddef>
#include <map>

#include "sid.hpp"
#include "util.hpp"

namespace pm {

namespace {

bool is_match_ace(const ACE_HEADER* h, PSID from) {
    if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != ACCESS_DENIED_ACE_TYPE) return false;
    auto* a = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(h);  // misma disposicion para ACCESS_DENIED_ACE
    return EqualSid(const_cast<DWORD*>(&a->SidStart), from) != 0;
}

std::wstring long_path(const std::wstring& p) {
    if (p.rfind(L"\\\\?\\", 0) == 0) return p;
    if (p.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + p.substr(2);
    return L"\\\\?\\" + p;
}

const SECURITY_INFORMATION kReadInfo = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

}  // namespace

bool translate_sd(const std::vector<BYTE>& rel, PSID from, PSID to, SdPatch& out) {
    auto sd = (PSECURITY_DESCRIPTOR)rel.data();
    PSID owner = nullptr;
    BOOL defaulted = FALSE, present = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorOwner(sd, &owner, &defaulted);
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
    DWORD rev = 0;
    GetSecurityDescriptorControl(sd, &ctrl, &rev);

    const bool owner_change = owner && EqualSid(owner, from);

    const DWORD to_len = GetLengthSid(to);
    const size_t new_ace_size = offsetof(ACCESS_ALLOWED_ACE, SidStart) + to_len;
    std::vector<BYTE> new_acl;
    bool dacl_change = false;

    if (present && dacl && dacl->AceCount > 0) {
        std::vector<ACE_HEADER*> aces(dacl->AceCount);
        size_t total = sizeof(ACL);
        for (DWORD i = 0; i < dacl->AceCount; ++i) {
            if (!GetAce(dacl, i, reinterpret_cast<LPVOID*>(&aces[i]))) return false;
            if (is_match_ace(aces[i], from)) {
                dacl_change = true;
                total += new_ace_size;
            } else {
                total += aces[i]->AceSize;
            }
        }
        if (dacl_change) {
            total = (total + 3) & ~static_cast<size_t>(3);
            new_acl.assign(total, 0);
            auto* na = reinterpret_cast<PACL>(new_acl.data());
            if (!InitializeAcl(na, (DWORD)total, dacl->AclRevision)) return false;
            for (DWORD i = 0; i < dacl->AceCount; ++i) {
                if (is_match_ace(aces[i], from)) {
                    std::vector<BYTE> t(new_ace_size, 0);
                    auto* ta = reinterpret_cast<ACCESS_ALLOWED_ACE*>(t.data());
                    ta->Header = *aces[i];
                    ta->Header.AceSize = (WORD)new_ace_size;
                    ta->Mask = reinterpret_cast<ACCESS_ALLOWED_ACE*>(aces[i])->Mask;
                    CopySid(to_len, reinterpret_cast<PSID>(&ta->SidStart), to);
                    if (!AddAce(na, dacl->AclRevision, MAXDWORD, t.data(), (DWORD)new_ace_size)) return false;
                } else {
                    if (!AddAce(na, dacl->AclRevision, MAXDWORD, aces[i], aces[i]->AceSize)) return false;
                }
            }
        }
    }

    if (!owner_change && !dacl_change) return false;

    SECURITY_DESCRIPTOR abs_sd{};
    InitializeSecurityDescriptor(&abs_sd, SECURITY_DESCRIPTOR_REVISION);
    if (owner_change) SetSecurityDescriptorOwner(&abs_sd, to, FALSE);
    if (dacl_change) SetSecurityDescriptorDacl(&abs_sd, TRUE, reinterpret_cast<PACL>(new_acl.data()), FALSE);

    const bool protect = (ctrl & SE_DACL_PROTECTED) != 0;
    SECURITY_DESCRIPTOR_CONTROL want = 0;
    if (protect) want |= SE_DACL_PROTECTED;
    if (ctrl & SE_DACL_AUTO_INHERITED) want |= SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
    SetSecurityDescriptorControl(&abs_sd, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ, want);

    DWORD len = 0;
    MakeSelfRelativeSD(&abs_sd, nullptr, &len);
    out.sd.assign(len, 0);
    if (!MakeSelfRelativeSD(&abs_sd, out.sd.data(), &len)) return false;

    out.info = 0;
    if (owner_change) out.info |= OWNER_SECURITY_INFORMATION;
    if (dacl_change)
        out.info |= DACL_SECURITY_INFORMATION | (protect ? PROTECTED_DACL_SECURITY_INFORMATION
                                                          : UNPROTECTED_DACL_SECURITY_INFORMATION);
    return true;
}

// ---------------------------------------------------------------------------------------- carpetas

namespace {

struct FromTo {
    std::vector<BYTE> from, to;
    HKEY root = HKEY_LOCAL_MACHINE;  // solo registro: raiz bajo la que cuelga el hive recorrido
    bool delete_only = false;        // solo registro: no traducir permisos, solo borrar las claves UserChoice
    PSID f() { return from.data(); }
    PSID t() { return to.data(); }
};

// Devuelve 1 si se cambio, 0 si no hacia falta, -1 si hubo un error (GetLastError conserva la causa).
int translate_one_file(const std::wstring& path, FromTo& ft) {
    HANDLE h = CreateFileW(long_path(path).c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    int result = -1;
    DWORD need = 0;
    GetKernelObjectSecurity(h, kReadInfo, nullptr, 0, &need);
    std::vector<BYTE> sd(need ? need : 1);
    if (GetKernelObjectSecurity(h, kReadInfo, sd.data(), (DWORD)sd.size(), &need)) {
        SdPatch patch;
        if (!translate_sd(sd, ft.f(), ft.t(), patch)) result = 0;
        else if (SetKernelObjectSecurity(h, patch.info, patch.sd.data())) result = 1;
    }
    DWORD err = GetLastError();
    CloseHandle(h);
    SetLastError(err);
    return result;
}

void count_file(const std::wstring& path, FromTo& ft, TranslateResult& r) {
    ++r.scanned;
    int rc = translate_one_file(path, ft);
    if (rc == 1) {
        ++r.changed;
    } else if (rc < 0) {
        DWORD err = GetLastError();
        if (++r.failed <= 10) warn("No se pudo traducir el SID en " + narrow(path) + ": " + win_error(err));
    }
}

void walk_files(const std::wstring& dir, FromTo& ft, TranslateResult& r) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(long_path(dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring full = dir + L"\\" + name;
        count_file(full, ft, r);  // tambien las junctions (sobre el propio enlace, sin seguirlo)
        const bool reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !reparse) walk_files(full, ft, r);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

}  // namespace

TranslateResult translate_tree_files(const std::wstring& root, const std::string& from, const std::string& to) {
    FromTo ft{sid_from_string(from), sid_from_string(to)};
    TranslateResult r;
    std::wstring base = root;
    while (base.size() > 3 && base.back() == L'\\') base.pop_back();
    count_file(base, ft, r);
    walk_files(base, ft, r);
    return r;
}

// ---------------------------------------------------------------------------------------- registro

namespace {

LONG open_key_sec(HKEY parent, const std::wstring& name, REGSAM access, HKEY* out) {
    LONG rc = RegOpenKeyExW(parent, name.c_str(), 0, access, out);
    if (rc == ERROR_ACCESS_DENIED) rc = RegOpenKeyExW(parent, name.c_str(), REG_OPTION_BACKUP_RESTORE, access, out);
    return rc;
}

// Claves cuya ACL no deja escribir ni a Administradores (p. ej. ...\UserChoice, protegidas a proposito por
// Windows): se toma la propiedad (SeTakeOwnership concede WRITE_OWNER), el propietario ya puede escribir la
// DACL y despues se aplica el parche. Si el propietario original no iba a cambiar, se restaura.
LONG patch_key_taking_ownership(HKEY parent, const std::wstring& name, const SdPatch& patch, PSID original_owner) {
    auto admins = well_known_sid(WinBuiltinAdministratorsSid);
    auto set_owner = [&](HKEY k, PSID owner) {
        SECURITY_DESCRIPTOR s{};
        InitializeSecurityDescriptor(&s, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&s, owner, FALSE);
        return RegSetKeySecurity(k, OWNER_SECURITY_INFORMATION, &s);
    };

    HKEY w = nullptr;
    LONG rc = RegOpenKeyExW(parent, name.c_str(), 0, WRITE_OWNER, &w);
    if (rc != ERROR_SUCCESS) return rc;
    rc = set_owner(w, admins.data());
    RegCloseKey(w);
    if (rc != ERROR_SUCCESS) return rc;

    rc = RegOpenKeyExW(parent, name.c_str(), 0, WRITE_DAC | WRITE_OWNER, &w);
    if (rc != ERROR_SUCCESS) return rc;
    rc = RegSetKeySecurity(w, patch.info, const_cast<BYTE*>(patch.sd.data()));
    if (rc == ERROR_SUCCESS && !(patch.info & OWNER_SECURITY_INFORMATION) && original_owner)
        rc = set_owner(w, original_owner);
    RegCloseKey(w);
    return rc;
}

bool is_user_choice(const std::wstring& name) {
    return _wcsicmp(name.c_str(), L"UserChoice") == 0 || _wcsicmp(name.c_str(), L"UserChoiceLatest") == 0;
}

// Borra una clave protegida a proposito por Windows (UserChoice): toma la propiedad, se concede control total
// y la elimina. `shown` es la ruta bajo `root`. Si falla, `why` dice en que paso.
bool force_delete_key(HKEY root, const std::wstring& shown, std::string& why) {
    if (RegDeleteTreeW(root, shown.c_str()) == ERROR_SUCCESS) return true;

    const wchar_t* prefix = root == HKEY_CURRENT_USER ? L"CURRENT_USER\\" : L"MACHINE\\";
    std::wstring path = prefix + shown;
    auto admins = well_known_sid(WinBuiltinAdministratorsSid);

    DWORD e = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
                                    admins.data(), nullptr, nullptr, nullptr);
    if (e != ERROR_SUCCESS) {
        why = "tomar la propiedad: " + win_error(e);
        return false;
    }

    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&ea.Trustee, admins.data());
    PACL acl = nullptr;
    e = SetEntriesInAclW(1, &ea, nullptr, &acl);
    if (e != ERROR_SUCCESS) {
        why = "construir la ACL: " + win_error(e);
        return false;
    }
    e = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_REGISTRY_KEY,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl,
                              nullptr);
    LocalFree(acl);
    if (e != ERROR_SUCCESS) {
        why = "conceder control total: " + win_error(e);
        return false;
    }

    LONG rc = RegDeleteTreeW(root, shown.c_str());
    if (rc != ERROR_SUCCESS) {
        why = "borrar la clave: " + win_error((DWORD)rc);
        return false;
    }
    return true;
}

void walk_key(HKEY parent, const std::wstring& name, const std::wstring& shown, FromTo& ft, TranslateResult& r) {
    ++r.scanned;
    if (is_user_choice(name)) {
        // Windows firma el contenido de estas claves con un hash ligado al SID del usuario: tras cambiar de SID
        // es invalido y la clave esta protegida a proposito. Si se deja, Edge y Windows intentan repararla una y
        // otra vez, avisando de cambios de asociaciones cada pocos milisegundos (iconos que parpadean). Se borra
        // siempre y el sistema la crea de nuevo, correctamente.
        std::string why;
        if (force_delete_key(ft.root, shown, why)) {
            ++r.deleted;
            info("Eliminada (el hash queda invalido al cambiar de SID; se recreara sola): " + narrow(shown));
        } else {
            ++r.skipped;
            warn("No se pudo eliminar " + narrow(shown) + " (" + why + ")");
        }
        return;
    }
    HKEY h = nullptr;
    bool write_access = true;
    LONG rc = RegOpenKeyExW(parent, name.c_str(), 0, READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_ENUMERATE_SUB_KEYS, &h);
    if (rc == ERROR_ACCESS_DENIED) {
        // Solo lectura/enumeracion (con SeBackup); la escritura se hara tomando la propiedad
        write_access = false;
        rc = RegOpenKeyExW(parent, name.c_str(), REG_OPTION_BACKUP_RESTORE, READ_CONTROL | KEY_ENUMERATE_SUB_KEYS, &h);
    }
    if (rc != ERROR_SUCCESS) {
        if (++r.failed <= 10) warn("No se pudo abrir la clave " + narrow(shown) + ": " + win_error((DWORD)rc));
        return;
    }

    if (!ft.delete_only) {
        DWORD need = 0;
        RegGetKeySecurity(h, kReadInfo, nullptr, &need);
        std::vector<BYTE> sd(need ? need : 1);
        DWORD len = (DWORD)sd.size();
        rc = RegGetKeySecurity(h, kReadInfo, sd.data(), &len);
        if (rc == ERROR_SUCCESS) {
            SdPatch patch;
            if (translate_sd(sd, ft.f(), ft.t(), patch)) {
                if (write_access) {
                    rc = RegSetKeySecurity(h, patch.info, patch.sd.data());
                    if (rc == ERROR_ACCESS_DENIED) write_access = false;
                }
                if (!write_access) {
                    PSID owner = nullptr;
                    BOOL def = FALSE;
                    GetSecurityDescriptorOwner(sd.data(), &owner, &def);
                    rc = patch_key_taking_ownership(parent, name, patch, owner);
                }
                if (rc == ERROR_SUCCESS) ++r.changed;
            }
        }
        if (rc != ERROR_SUCCESS && ++r.failed <= 10)
            warn("No se pudo traducir el SID en la clave " + narrow(shown) + ": " + win_error((DWORD)rc));
    }

    std::vector<std::wstring> children;
    wchar_t buf[512];
    for (DWORD i = 0;; ++i) {
        DWORD n = 512;
        LONG e = RegEnumKeyExW(h, i, buf, &n, nullptr, nullptr, nullptr, nullptr);
        if (e == ERROR_NO_MORE_ITEMS) break;
        if (e == ERROR_SUCCESS) children.emplace_back(buf, n);
    }
    for (auto& c : children) walk_key(h, c, shown + L"\\" + c, ft, r);
    RegCloseKey(h);
}

}  // namespace

TranslateResult translate_tree_hive(const std::wstring& hive_name, const std::string& from, const std::string& to,
                                    HKEY root) {
    FromTo ft{sid_from_string(from), sid_from_string(to)};
    ft.root = root;
    TranslateResult r;
    walk_key(root, hive_name, hive_name, ft, r);
    return r;
}

TranslateResult delete_user_choice_keys(const std::wstring& hive_name, HKEY root) {
    // Los SID no se usan en este modo: se pasan unos cualesquiera solo para construir el contexto
    FromTo ft{sid_from_string("S-1-5-21-1-1-1-1"), sid_from_string("S-1-5-21-1-1-1-2")};
    ft.root = root;
    ft.delete_only = true;
    TranslateResult r;
    walk_key(root, hive_name, hive_name, ft, r);
    return r;
}

namespace {

void tally_owners(HKEY parent, const std::wstring& name, const std::string& exclude,
                  std::map<std::string, size_t>& counts, size_t* user_choice = nullptr) {
    if (user_choice && is_user_choice(name)) ++*user_choice;
    HKEY h = nullptr;
    LONG rc = RegOpenKeyExW(parent, name.c_str(), 0, READ_CONTROL | KEY_ENUMERATE_SUB_KEYS, &h);
    if (rc == ERROR_ACCESS_DENIED)
        rc = RegOpenKeyExW(parent, name.c_str(), REG_OPTION_BACKUP_RESTORE, READ_CONTROL | KEY_ENUMERATE_SUB_KEYS, &h);
    if (rc != ERROR_SUCCESS) return;

    DWORD need = 0;
    RegGetKeySecurity(h, OWNER_SECURITY_INFORMATION, nullptr, &need);
    std::vector<BYTE> sd(need ? need : 1);
    DWORD len = (DWORD)sd.size();
    if (RegGetKeySecurity(h, OWNER_SECURITY_INFORMATION, sd.data(), &len) == ERROR_SUCCESS) {
        PSID owner = nullptr;
        BOOL def = FALSE;
        GetSecurityDescriptorOwner(sd.data(), &owner, &def);
        if (owner) {
            std::string s = sid_to_string(owner);
            if (s.rfind("S-1-5-21-", 0) == 0 && s != exclude) ++counts[s];
        }
    }
    std::vector<std::wstring> children;
    wchar_t buf[512];
    for (DWORD i = 0;; ++i) {
        DWORD n = 512;
        LONG e = RegEnumKeyExW(h, i, buf, &n, nullptr, nullptr, nullptr, nullptr);
        if (e == ERROR_NO_MORE_ITEMS) break;
        if (e == ERROR_SUCCESS) children.emplace_back(buf, n);
    }
    for (auto& c : children) tally_owners(h, c, exclude, counts, user_choice);
    RegCloseKey(h);
}

}  // namespace

HiveLeftovers scan_hive_leftovers(const std::wstring& hive_name, const std::string& to, HKEY root) {
    std::map<std::string, size_t> counts;
    HiveLeftovers r;
    tally_owners(root, hive_name, to, counts, &r.user_choice);
    size_t best = 0;
    for (auto& [sid, c] : counts) {
        r.foreign_keys += c;
        if (c > best) r.foreign_sid = sid, best = c;
    }
    return r;
}

std::string detect_foreign_owner_sid(const std::wstring& hive_name, const std::string& exclude, HKEY root) {
    std::map<std::string, size_t> counts;
    tally_owners(root, hive_name, exclude, counts);
    std::string best;
    size_t n = 0;
    for (auto& [sid, c] : counts)
        if (c > n) best = sid, n = c;
    return best;
}

std::string detect_hive_user_sid(const std::wstring& hive_name, HKEY root) {
    HKEY h = nullptr;
    if (open_key_sec(root, hive_name, READ_CONTROL, &h) != ERROR_SUCCESS) return "";
    DWORD need = 0;
    RegGetKeySecurity(h, kReadInfo, nullptr, &need);
    std::vector<BYTE> sd(need ? need : 1);
    DWORD len = (DWORD)sd.size();
    std::string found;
    if (RegGetKeySecurity(h, kReadInfo, sd.data(), &len) == ERROR_SUCCESS) {
        auto is_account = [](const std::string& s) { return s.rfind("S-1-5-21-", 0) == 0; };
        PSID owner = nullptr;
        BOOL def = FALSE, present = FALSE;
        PACL dacl = nullptr;
        GetSecurityDescriptorOwner(sd.data(), &owner, &def);
        if (owner) {
            std::string s = sid_to_string(owner);
            if (is_account(s)) found = s;
        }
        if (found.empty()) {
            GetSecurityDescriptorDacl(sd.data(), &present, &dacl, &def);
            for (DWORD i = 0; present && dacl && i < dacl->AceCount && found.empty(); ++i) {
                ACE_HEADER* a = nullptr;
                if (!GetAce(dacl, i, reinterpret_cast<LPVOID*>(&a))) break;
                if (a->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
                std::string s = sid_to_string(&reinterpret_cast<ACCESS_ALLOWED_ACE*>(a)->SidStart);
                if (is_account(s)) found = s;
            }
        }
    }
    RegCloseKey(h);
    return found;
}

}  // namespace pm
