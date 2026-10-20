#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace pm {

struct Profile {
    std::string sid;
    std::wstring path;
    std::string account;  // DOMINIO\usuario o "???" si no se resuelve
    bool loaded = false;  // hive montado en HKEY_USERS
    bool exists = false;  // la carpeta existe
};

std::string sid_to_string(PSID sid);
std::vector<BYTE> sid_from_string(const std::string& s);
std::vector<BYTE> well_known_sid(WELL_KNOWN_SID_TYPE type);
std::string sid_to_account(const std::string& sid);

bool is_profile_loaded(const std::string& sid);
std::vector<Profile> list_profiles();

// Resuelve el SID de una cuenta de dominio consultando directamente al DC (sin LDAP, sin estar unido).
// Abre una sesión autenticada contra \dc\IPC$ con las credenciales dadas y usa LookupAccountName.
std::string resolve_domain_sid(const std::string& dc, const std::string& domain, const std::string& user,
                               const std::string& admin, const std::string& password);

}  // namespace pm
