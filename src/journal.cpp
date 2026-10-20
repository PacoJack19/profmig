#include "journal.hpp"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <vector>

#include "util.hpp"

namespace fs = std::filesystem;

namespace pm {

namespace {
const wchar_t* kDir = L"C:\\ProfMig\\journal";
}

void journal_write(Journal& j) {
    std::error_code ec;
    fs::create_directories(kDir, ec);
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t name[64];
    swprintf(name, 64, L"migration_%04d%02d%02d_%02d%02d%02d.txt", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
             t.wSecond);
    fs::path p = fs::path(kDir) / name;
    std::ofstream f(p, std::ios::binary);
    if (!f) throw Fail("No se pudo escribir el diario " + narrow(p.wstring()));
    f << "old_sid=" << j.old_sid << "\nnew_sid=" << j.new_sid << "\naccount=" << j.account << "\ndomain=" << j.domain
      << "\nuser=" << j.user << "\npath=" << narrow(j.path) << "\nbackup=" << narrow(j.backup)
      << "\nimported=" << (j.imported ? 1 : 0) << "\n";
    j.file = p.wstring();
}

std::optional<Journal> journal_last() {
    std::error_code ec;
    std::vector<fs::path> files;
    for (fs::directory_iterator it(kDir, ec), end; !ec && it != end; it.increment(ec))
        if (it->path().extension() == L".txt" && it->path().filename().wstring().rfind(L"migration_", 0) == 0)
            files.push_back(it->path());
    if (files.empty()) return std::nullopt;
    std::sort(files.begin(), files.end());

    std::ifstream f(files.back(), std::ios::binary);
    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos) kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    Journal j;
    j.old_sid = kv["old_sid"];
    j.new_sid = kv["new_sid"];
    j.account = kv["account"];
    j.domain = kv["domain"];
    j.user = kv["user"];
    j.path = widen(kv["path"]);
    j.backup = widen(kv["backup"]);
    j.imported = kv["imported"] == "1";
    j.file = files.back().wstring();
    return j;
}

void journal_mark_undone(const Journal& j) {
    std::error_code ec;
    fs::rename(j.file, j.file + L".undone", ec);
}

}  // namespace pm
