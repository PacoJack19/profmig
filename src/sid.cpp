#include "sid.hpp"

#include <sddl.h>
#include <winnetwk.h>

#include "util.hpp"

namespace pm {

static const wchar_t* kProfileList = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

std::string sid_to_string(PSID sid) {
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid, &s)) throw Fail("ConvertSidToStringSid: " + win_error(GetLastError()));
    std::string r = narrow(s);
    LocalFree(s);
    return r;
}

std::vector<BYTE> sid_from_string(const std::string& s) {
    PSID p = nullptr;
    if (!ConvertStringSidToSidW(widen(s).c_str(), &p)) throw Fail("SID invalido '" + s + "': " + win_error(GetLastError()));
    DWORD n = GetLengthSid(p);
    std::vector<BYTE> v((BYTE*)p, (BYTE*)p + n);
    LocalFree(p);
    return v;
}

std::vector<BYTE> well_known_sid(WELL_KNOWN_SID_TYPE type) {
    DWORD n = SECURITY_MAX_SID_SIZE;
    std::vector<BYTE> v(n);
    if (!CreateWellKnownSid(type, nullptr, v.data(), &n)) throw Fail("CreateWellKnownSid: " + win_error(GetLastError()));
    v.resize(n);
    return v;
}

std::string sid_to_account(const std::string& sid_str) {
    try {
        auto sid = sid_from_string(sid_str);
        wchar_t name[256], dom[256];
        DWORD nn = 256, dn = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, sid.data(), name, &nn, dom, &dn, &use))
            return narrow(std::wstring(dom) + L"\\" + name);
    } catch (...) {
    }
    return "???";
}

bool is_profile_loaded(const std::string& sid) {
    HKEY k = nullptr;
    LONG r = RegOpenKeyExW(HKEY_USERS, widen(sid).c_str(), 0, KEY_READ, &k);
    if (r == ERROR_SUCCESS) RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

std::vector<Profile> list_profiles() {
    std::vector<Profile> out;
    HKEY base = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProfileList, 0, KEY_READ, &base) != ERROR_SUCCESS) return out;
    wchar_t name[256];
    for (DWORD i = 0;; ++i) {
        DWORD len = 256;
        if (RegEnumKeyExW(base, i, name, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        std::wstring sid(name, len);
        if (sid.rfind(L"S-1-5-21-", 0) != 0) continue;  // solo cuentas locales/de dominio, no servicios ni .bak
        if (sid.size() > 4 && sid.compare(sid.size() - 4, 4, L".bak") == 0) continue;

        HKEY k = nullptr;
        if (RegOpenKeyExW(base, sid.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
        wchar_t raw[MAX_PATH * 2];
        DWORD sz = sizeof raw - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(k, L"ProfileImagePath", nullptr, &type, (LPBYTE)raw, &sz) == ERROR_SUCCESS) {
            raw[sz / sizeof(wchar_t)] = L'\0';
            wchar_t expanded[MAX_PATH * 2];
            ExpandEnvironmentStringsW(raw, expanded, MAX_PATH * 2);
            Profile p;
            p.sid = narrow(sid);
            p.path = expanded;
            p.account = sid_to_account(p.sid);
            p.loaded = is_profile_loaded(p.sid);
            DWORD attr = GetFileAttributesW(p.path.c_str());
            p.exists = attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
            out.push_back(std::move(p));
        }
        RegCloseKey(k);
    }
    RegCloseKey(base);
    return out;
}

std::string resolve_domain_sid(const std::string& dc, const std::string& domain, const std::string& user,
                               const std::string& admin, const std::string& password) {
    std::wstring ipc = L"\\\\" + widen(dc) + L"\\IPC$";
    std::string wnet_user = admin;
    if (admin.find('\\') == std::string::npos && admin.find('@') == std::string::npos) wnet_user = admin + "@" + domain;
    std::wstring wuser = widen(wnet_user), wpass = widen(password);

    NETRESOURCEW nr{};
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpRemoteName = ipc.data();
    DWORD rc = WNetAddConnection2W(&nr, wpass.c_str(), wuser.c_str(), 0);
    bool added = rc == NO_ERROR;
    // 1219: ya hay una sesion con otras credenciales contra ese servidor; se intenta con la existente
    if (!added && rc != ERROR_SESSION_CREDENTIAL_CONFLICT)
        throw Fail("No se pudo autenticar contra el DC '" + dc + "': " + win_error(rc));

    std::string result;
    std::string last_err;
    for (const std::string& candidate : {domain + "\\" + user, user}) {
        BYTE sid[SECURITY_MAX_SID_SIZE];
        DWORD sn = sizeof sid, dn = 256;
        wchar_t dom[256];
        SID_NAME_USE use;
        if (LookupAccountNameW(widen(dc).c_str(), widen(candidate).c_str(), sid, &sn, dom, &dn, &use)) {
            if (use != SidTypeUser) {
                last_err = "'" + candidate + "' no es una cuenta de usuario";
                continue;
            }
            result = sid_to_string(sid);
            break;
        }
        last_err = "'" + candidate + "': " + win_error(GetLastError());
    }
    if (added) WNetCancelConnection2W(ipc.c_str(), 0, TRUE);
    if (result.empty()) throw Fail("No se pudo resolver el SID de " + user + " en " + domain + ". " + last_err);
    return result;
}

}  // namespace pm
