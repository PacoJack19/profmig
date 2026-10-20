// Test de exportar/extraer perfiles (no requiere administrador). Crea su propio arbol de prueba en la carpeta temporal:
// un perfil con NTUSER.DAT, un archivo con tildes, una carpeta Temp (excluida) y una junction (no debe seguirse).
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "transfer.hpp"
#include "util.hpp"

namespace fs = std::filesystem;
using namespace pm;

static int g_fail = 0;
static void check(bool ok, const std::string& what) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

static void write_file(const fs::path& p, const char* text) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream(p, std::ios::binary) << text;
}

int main() {
    std::error_code ec;
    fs::path base = fs::temp_directory_path() / L"profmig_transfer_test";
    fs::path src = base / L"src", zip = base / L"perfil.zip", dst = base / L"dst";
    fs::path junction = src / L"Application Data";

    // Limpieza previa (si quedo una junction de una ejecucion interrumpida, se quita sin seguirla)
    if (fs::exists(junction, ec)) run(L"cmd.exe /c rmdir \"" + junction.wstring() + L"\"");
    fs::remove_all(base, ec);

    write_file(src / L"NTUSER.DAT", "hive");
    write_file(src / L"Documents" / L"a.txt", "a");
    write_file(src / L"Documents" / L"año ñandú.txt", "tildes");
    write_file(src / L"AppData" / L"Local" / L"Temp" / L"x.tmp", "temporal");
    write_file(src / L"AppData" / L"Roaming" / L"Microsoft" / L"Templates" / L"t.dotx", "plantilla");
    run(L"cmd.exe /c mklink /J \"" + junction.wstring() + L"\" \"" + (src / L"AppData" / L"Roaming").wstring() + L"\"");
    check(fs::exists(junction, ec), "preparacion: la junction de prueba existe");

    try {
        export_profile(src.wstring(), zip.wstring());
        check(fs::exists(zip, ec) && fs::file_size(zip, ec) > 0, "export: se crea el .zip");
        extract_profile(zip.wstring(), dst.wstring());
    } catch (const std::exception& e) {
        std::printf("ERROR: %s\n", e.what());
        ++g_fail;
    }

    check(fs::exists(dst / L"NTUSER.DAT", ec), "extraccion: NTUSER.DAT");
    check(fs::exists(dst / L"Documents" / L"a.txt", ec), "extraccion: archivo normal");
    check(fs::exists(dst / L"Documents" / L"año ñandú.txt", ec), "extraccion: nombre con tildes");
    check(fs::exists(dst / L"AppData" / L"Roaming" / L"Microsoft" / L"Templates" / L"t.dotx", ec),
          "extraccion: carpeta real 'Templates' conservada");
    check(!fs::exists(dst / L"AppData" / L"Local" / L"Temp" / L"x.tmp", ec), "export: AppData\\Local\\Temp excluida");
    check(!fs::exists(dst / L"Application Data" / L"Microsoft" / L"Templates" / L"t.dotx", ec),
          "export: la junction no se sigue (no duplica datos)");

    // Un zip sin NTUSER.DAT no es un perfil: debe rechazarse y no dejar carpetas a medias
    fs::path bad_src = base / L"sin_hive", bad_zip = base / L"malo.zip", bad_dst = base / L"dst_malo";
    write_file(bad_src / L"Documents" / L"x.txt", "x");
    bool rejected = false;
    try {
        export_profile(bad_src.wstring(), bad_zip.wstring());
        extract_profile(bad_zip.wstring(), bad_dst.wstring());
    } catch (const Fail&) {
        rejected = true;
    }
    check(rejected && !fs::exists(bad_dst, ec), "extraccion: un zip sin NTUSER.DAT se rechaza y no deja carpeta");

    run(L"cmd.exe /c rmdir \"" + junction.wstring() + L"\"");  // quitar la junction antes de borrar el arbol
    fs::remove_all(base, ec);

    std::printf("\n%s (%d fallo(s))\n", g_fail ? "RESULTADO: FALLO" : "RESULTADO: TODO OK", g_fail);
    return g_fail ? 1 : 0;
}
