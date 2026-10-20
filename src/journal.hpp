#pragma once
#include <optional>
#include <string>

namespace pm {

// Diario de cada migracion (C:\ProfMig\journal) para poder deshacerla.
struct Journal {
    std::string old_sid, new_sid, account, domain, user;
    std::wstring path, backup;  // carpeta del perfil y .reg de ProfileList
    bool imported = false;      // true si el perfil venia de un .zip (no hay SID viejo)
    std::wstring file;          // fichero del diario (lo rellena journal_write / journal_last)
};

void journal_write(Journal& j);
std::optional<Journal> journal_last();  // la ultima migracion sin deshacer
void journal_mark_undone(const Journal& j);

}  // namespace pm
