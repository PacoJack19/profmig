#include "transfer.hpp"

#include <filesystem>
#include <vector>

#include "util.hpp"

namespace fs = std::filesystem;

namespace pm {

namespace {

std::wstring tar_exe() {
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    return std::wstring(sys) + L"\\tar.exe";  // el de Windows (bsdtar); en el PATH puede haber otro tar
}

// libarchive trata * ? [ ] \ como comodines en --exclude
std::wstring escape_pattern(const std::wstring& s) {
    std::wstring r;
    for (wchar_t c : s) {
        if (c == L'*' || c == L'?' || c == L'[' || c == L']' || c == L'\\') r += L'\\';
        r += c;
    }
    return r;
}

void collect_reparse_points(const fs::path& root, const fs::path& dir, std::vector<std::wstring>& out) {
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        DWORD attr = GetFileAttributesW(it->path().c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
            out.push_back(it->path().lexically_relative(root).generic_wstring());
        } else if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            collect_reparse_points(root, it->path(), out);
        }
    }
}

std::string tail(const std::string& s, size_t n = 600) { return s.size() > n ? "..." + s.substr(s.size() - n) : s; }

}  // namespace

void export_profile(const std::wstring& dir, const std::wstring& zip) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) throw Fail("La carpeta del perfil no existe: " + narrow(dir));
    if (fs::exists(zip, ec)) throw Fail("El archivo de salida ya existe: " + narrow(zip));
    fs::create_directories(fs::path(zip).parent_path(), ec);

    std::vector<std::wstring> skip;
    collect_reparse_points(dir, dir, skip);
    info("Enlaces/junctions omitidos: " + std::to_string(skip.size()));

    std::wstring cmd = L"\"" + tar_exe() + L"\" -a -cf \"" + zip + L"\" -C \"" + dir + L"\"";
    for (auto& s : skip) cmd += L" --exclude \"^./" + escape_pattern(s) + L"\"";
    for (const wchar_t* junk : {L"AppData/Local/Temp", L"AppData/Local/Microsoft/Windows/INetCache"})
        cmd += std::wstring(L" --exclude \"^./") + junk + L"\"";
    cmd += L" .";

    info("Empaquetando " + narrow(dir) + " -> " + narrow(zip) + " (puede tardar)");
    std::string out;
    int rc = run(cmd, &out, 6 * 3600 * 1000);
    if (rc != 0) {
        fs::remove(zip, ec);
        throw Fail("tar fallo (codigo " + std::to_string(rc) + "): " + tail(out));
    }
    std::uintmax_t size = fs::file_size(zip, ec);
    ok("Perfil exportado: " + narrow(zip) + " (" + std::to_string(size / (1024 * 1024)) + " MB)");
}

void extract_profile(const std::wstring& zip, const std::wstring& dest) {
    std::error_code ec;
    if (!fs::is_regular_file(zip, ec)) throw Fail("No existe el archivo: " + narrow(zip));
    if (fs::exists(dest, ec)) throw Fail("La carpeta destino ya existe: " + narrow(dest));
    fs::create_directories(dest, ec);
    if (ec) throw Fail("No se pudo crear " + narrow(dest) + ": " + ec.message());

    std::string out;
    std::wstring cmd = L"\"" + tar_exe() + L"\" -xf \"" + zip + L"\" -C \"" + dest + L"\"";
    int rc = run(cmd, &out, 6 * 3600 * 1000);
    if (rc != 0) {
        fs::remove_all(dest, ec);
        throw Fail("No se pudo extraer el perfil (codigo " + std::to_string(rc) + "): " + tail(out));
    }
    if (!fs::exists(fs::path(dest) / L"NTUSER.DAT", ec)) {
        fs::remove_all(dest, ec);
        throw Fail("El archivo no contiene NTUSER.DAT: no parece un perfil de Windows exportado.");
    }
    ok("Perfil extraido en " + narrow(dest));
}

}  // namespace pm
