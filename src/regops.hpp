#pragma once
#include <windows.h>
#include <string>

namespace pm {

// ---- ProfileList / ProfileGuid ----
// Exporta ProfileList y ProfileGuid con reg.exe. Devuelve la ruta del .reg de ProfileList.
std::wstring backup_profile_registry(const std::wstring& dir);
void restore_profile_registry(const std::wstring& profilelist_reg);

// Crea ProfileList\<new> con los valores de <old>, la ruta del perfil y el valor binario 'Sid' correcto.
void reassign_profile_list(const std::string& old_sid, const std::string& new_sid, const std::wstring& path);
void update_profile_guid_map(const std::string& old_sid, const std::string& new_sid);
void delete_profile_key(const std::string& sid);

void set_default_logon(const std::string& domain, const std::string& user);

// ---- Hives de usuario montados temporalmente en HKLM\<name> ----
class Hive {
public:
    Hive(const std::wstring& name, const std::wstring& file);
    ~Hive();
    Hive(const Hive&) = delete;
    Hive& operator=(const Hive&) = delete;
    bool unload();  // con reintentos; true si quedó desmontado
    const std::wstring& name() const { return name_; }

private:
    std::wstring name_;
    bool loaded_ = false;
};

void hive_normalize_shell_folders(const Hive& h, const std::wstring& profile_path);
void hive_purge_m365(const Hive& h);
// Directivas de usuario del dominio anterior que quedan "tatuadas" en el hive (fondo, restricciones...).
void hive_purge_user_policies(const Hive& h);
void hive_inject_runonce(const Hive& h);

}  // namespace pm
