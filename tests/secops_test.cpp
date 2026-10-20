// Test de la traduccion de SID. No requiere administrador:
//  1) logica pura sobre descriptores construidos desde SDDL (SID distintos);
//  2) mecanica real sobre una carpeta y claves de registro propias, con from == to (el resultado debe ser identico).
#include <aclapi.h>
#include <sddl.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

#include "secops.hpp"
#include "sid.hpp"
#include "util.hpp"

using namespace pm;
namespace fs = std::filesystem;

static int g_fail = 0;
static void check(bool ok, const std::string& what) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

static std::vector<BYTE> sd_from_sddl(const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) return {};
    std::vector<BYTE> v((BYTE*)sd, (BYTE*)sd + GetSecurityDescriptorLength(sd));
    LocalFree(sd);
    return v;
}

static std::wstring sddl_of(const std::vector<BYTE>& sd, DWORD info) {
    LPWSTR s = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW((PSECURITY_DESCRIPTOR)sd.data(), SDDL_REVISION_1, info, &s,
                                                              nullptr))
        return L"<error>";
    std::wstring r = s;
    LocalFree(s);
    return r;
}

// Quita las banderas de control del SDDL (D:PAI -> D:) para comparar solo propietario y ACEs.
static std::wstring strip_flags(std::wstring s) {
    size_t d = s.find(L"D:");
    if (d == std::wstring::npos) return s;
    size_t p = d + 2;
    while (p < s.size() && s[p] != L'(') ++p;
    return s.substr(0, d + 2) + s.substr(p);
}

static std::string my_sid() {
    HANDLE tok = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
    DWORD n = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &n);
    std::vector<BYTE> buf(n);
    GetTokenInformation(tok, TokenUser, buf.data(), n, &n);
    CloseHandle(tok);
    return sid_to_string(((TOKEN_USER*)buf.data())->User.Sid);
}

static std::wstring file_sddl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    PSID o = nullptr;
    PACL d = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &o,
                              nullptr, &d, nullptr, &sd) != ERROR_SUCCESS)
        return L"<error>";
    LPWSTR s = nullptr;
    ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1,
                                                         OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &s,
                                                         nullptr);
    std::wstring r = s ? s : L"";
    LocalFree(s);
    LocalFree(sd);
    return r;
}

int main() {
    // ---- 1) logica pura
    {
        auto from = sid_from_string("S-1-5-21-1-2-3-1111"), to = sid_from_string("S-1-5-21-1-2-3-2222");
        auto sd = sd_from_sddl(L"O:S-1-5-21-1-2-3-1111D:PAI(A;OICI;FA;;;S-1-5-21-1-2-3-1111)(A;;FA;;;SY)"
                               L"(A;OICIID;KR;;;RC)(D;;DC;;;S-1-5-21-1-2-3-1111)(A;;KR;;;AC)");
        SdPatch p;
        bool changed = translate_sd(sd, from.data(), to.data(), p);
        check(changed, "translate_sd detecta SID a cambiar");
        check(strip_flags(sddl_of(p.sd, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) ==
                  L"O:S-1-5-21-1-2-3-2222D:(A;OICI;FA;;;S-1-5-21-1-2-3-2222)(A;;FA;;;SY)(A;OICIID;KR;;;RC)"
                  L"(D;;DC;;;S-1-5-21-1-2-3-2222)(A;;KR;;;AC)",
              "propietario y ACEs traducidos; ACEs de otros SID, orden y banderas intactos");
        check((p.info & PROTECTED_DACL_SECURITY_INFORMATION) != 0, "se conserva la DACL protegida");

        auto sd2 = sd_from_sddl(L"O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)");
        SdPatch p2;
        check(!translate_sd(sd2, from.data(), to.data(), p2), "sin SID origen: no hay cambios");

        auto sd3 = sd_from_sddl(L"O:BAD:AI(A;ID;FA;;;S-1-5-21-1-2-3-1111)");
        SdPatch p3;
        check(translate_sd(sd3, from.data(), to.data(), p3) && !(p3.info & OWNER_SECURITY_INFORMATION) &&
                  (p3.info & UNPROTECTED_DACL_SECURITY_INFORMATION),
              "ACE heredida traducida sin tocar el propietario ni la herencia");
    }

    const std::string me = my_sid();

    // ---- 2) mecanica sobre carpetas (from == to)
    {
        fs::path root = fs::temp_directory_path() / L"profmig_secops_test";
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::create_directories(root / L"sub" / L"deep", ec);
        std::ofstream(root / L"a.txt") << "x";
        std::ofstream(root / L"sub" / L"b.txt") << "x";
        std::ofstream(root / L"sub" / L"deep" / L"c.txt") << "x";
        // junction hacia sub: debe tratarse como un elemento, sin descender
        run(L"cmd.exe /c mklink /J \"" + (root / L"junction").wstring() + L"\" \"" + (root / L"sub").wstring() + L"\"");

        std::wstring before = file_sddl((root / L"sub" / L"b.txt").wstring());
        TranslateResult r = translate_tree_files(root.wstring(), me, me);
        // raiz + a.txt + sub + b.txt + deep + c.txt + junction = 7
        check(r.scanned == 7, "carpetas: 7 elementos recorridos (junction sin seguir), recorridos=" + std::to_string(r.scanned));
        check(r.failed == 0, "carpetas: 0 errores, errores=" + std::to_string(r.failed));
        check(r.changed > 0, "carpetas: se reescribieron descriptores (propietario == from)");
        std::wstring after = file_sddl((root / L"sub" / L"b.txt").wstring());
        check(before == after && before != L"<error>", "carpetas: el descriptor resultante es identico al original");
        if (before != after) {
            std::printf("   antes  : %s\n   despues: %s\n", narrow(before).c_str(), narrow(after).c_str());
        }
        run(L"cmd.exe /c rmdir \"" + (root / L"junction").wstring() + L"\"");
        fs::remove_all(root, ec);
    }

    // ---- 3) mecanica sobre registro (from == to)
    {
        HKEY k = nullptr;
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\a\\b", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &k,
                        nullptr);
        if (k) RegCloseKey(k);
        std::string detected = detect_hive_user_sid(L"Software\\ProfMigSecopsTest", HKEY_CURRENT_USER);
        check(detected == me, "registro: detect_hive_user_sid devuelve el SID propietario");
        TranslateResult r = translate_tree_hive(L"Software\\ProfMigSecopsTest", me, me, HKEY_CURRENT_USER);
        check(r.scanned == 3, "registro: 3 claves recorridas, recorridas=" + std::to_string(r.scanned));
        check(r.failed == 0, "registro: 0 errores, errores=" + std::to_string(r.failed));
        check(r.changed >= 1, "registro: claves reescritas");
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
    }

    // ---- 3b) deteccion del SID anterior (propietario mas frecuente distinto de `exclude`)
    {
        HKEY k = nullptr;
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\a\\b\\c", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &k,
                        nullptr);
        if (k) RegCloseKey(k);
        std::string found = detect_foreign_owner_sid(L"Software\\ProfMigSecopsTest", "S-1-5-21-1-2-3-9999", HKEY_CURRENT_USER);
        check(found == me, "SID anterior detectado = propietario de las claves");
        std::string none = detect_foreign_owner_sid(L"Software\\ProfMigSecopsTest", me, HKEY_CURRENT_USER);
        check(none.empty(), "si el unico propietario es el excluido no se detecta nada");
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
    }

    // ---- 3c) delete_user_choice_keys: solo borra UserChoice y no toca ningun permiso
    {
        HKEY k = nullptr;
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\UrlAssociations\\http\\UserChoice", 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &k, nullptr);
        if (k) RegCloseKey(k);
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\UrlAssociations\\http\\Otra", 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &k, nullptr);
        if (k) RegCloseKey(k);
        TranslateResult r = delete_user_choice_keys(L"Software\\ProfMigSecopsTest", HKEY_CURRENT_USER);
        check(r.deleted == 1 && r.changed == 0 && r.failed == 0,
              "solo UserChoice: 1 eliminada, 0 traducidas, 0 errores (eliminadas=" + std::to_string(r.deleted) +
                  ", traducidas=" + std::to_string(r.changed) + ")");
        HKEY probe = nullptr;
        bool kept = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\UrlAssociations\\http\\Otra", 0, KEY_READ,
                                  &probe) == ERROR_SUCCESS;
        if (kept && probe) RegCloseKey(probe);
        check(kept, "solo UserChoice: el resto de claves se conserva");
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
    }

    // ---- 3d) scan_hive_leftovers: cuenta propietarios ajenos y claves UserChoice
    {
        HKEY k = nullptr;
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\x\\UserChoice", 0, nullptr, 0, KEY_ALL_ACCESS,
                        nullptr, &k, nullptr);
        if (k) RegCloseKey(k);
        // raiz + x + UserChoice = 3 claves, todas propiedad del usuario actual
        HiveLeftovers a = scan_hive_leftovers(L"Software\\ProfMigSecopsTest", "S-1-5-21-1-2-3-9999", HKEY_CURRENT_USER);
        check(a.user_choice == 1 && a.foreign_keys == 3 && a.foreign_sid == me,
              "verificacion: 1 UserChoice y 3 claves con propietario ajeno al esperado (UserChoice=" +
                  std::to_string(a.user_choice) + ", ajenas=" + std::to_string(a.foreign_keys) + ")");
        HiveLeftovers b = scan_hive_leftovers(L"Software\\ProfMigSecopsTest", me, HKEY_CURRENT_USER);
        check(b.foreign_keys == 0 && b.foreign_sid.empty(),
              "verificacion: con el SID esperado como propietario no queda nada ajeno");
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
    }

    // ---- 4) UserChoice: se elimina siempre, con sus subclaves, y el resto del arbol se sigue recorriendo
    {
        HKEY k = nullptr;
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\FileExts\\.pdf\\UserChoice\\hijo", 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &k, nullptr);
        if (k) RegCloseKey(k);
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\FileExts\\.pdf\\OtraClave", 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &k, nullptr);
        if (k) RegCloseKey(k);
        TranslateResult r = translate_tree_hive(L"Software\\ProfMigSecopsTest", me, me, HKEY_CURRENT_USER);
        check(r.deleted == 1, "UserChoice: 1 clave eliminada, eliminadas=" + std::to_string(r.deleted));
        check(r.skipped == 0 && r.failed == 0, "UserChoice: sin omitidas ni errores");
        HKEY probe = nullptr;
        bool gone = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\FileExts\\.pdf\\UserChoice", 0, KEY_READ,
                                  &probe) != ERROR_SUCCESS;
        bool kept = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest\\FileExts\\.pdf\\OtraClave", 0, KEY_READ,
                                  &probe) == ERROR_SUCCESS;
        if (kept && probe) RegCloseKey(probe);
        check(gone, "UserChoice: la clave y su subclave ya no existen");
        check(kept, "UserChoice: las claves hermanas se conservan");
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ProfMigSecopsTest");
    }

    std::printf("\n%s (%d fallo(s))\n", g_fail ? "RESULTADO: FALLO" : "RESULTADO: TODO OK", g_fail);
    return g_fail ? 1 : 0;
}
