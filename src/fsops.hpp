#pragma once
#include <windows.h>
#include <accctrl.h>
#include <string>

namespace pm {

struct TreeResult {
    size_t changed = 0;
    size_t failed = 0;
};
// Solo para perfiles RECIEN EXTRAIDOS de un .zip (sin ACL propias que conservar): deja a new_sid como
// propietario con control total, junto a SYSTEM y Administradores, y los hijos solo con ACEs heredadas.
// Para migrar un perfil existente NO usar esto (descarta ACEs especiales): usar translate_tree_files.
TreeResult reassign_tree_security(const std::wstring& root, const std::string& new_sid);

// ---- Limpieza de contenido del perfil ----
size_t archive_outlook_ost(const std::wstring& profile);     // *.ost -> *.ost.old
size_t purge_credentials(const std::wstring& profile);       // Credentials y Vault (Roaming + Local)
size_t purge_m365_disk_caches(const std::wstring& profile);  // IdentityCache, OneAuth, TokenBroker...
size_t purge_icon_caches(const std::wstring& profile);       // IconCache.db, iconcache_*.db, thumbcache_*.db

}  // namespace pm
