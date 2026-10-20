#include "gui.hpp"

#include "util.hpp"
// clang-format off
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
// clang-format on

#include <atomic>
#include <cstdio>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include "journal.hpp"
#include "ldap.hpp"
#include "migrate.hpp"
#include "sid.hpp"
#include "ucpd.hpp"

namespace pm {

namespace {

enum Id {
    ID_LV = 100, ID_REFRESH, ID_SIZES, ID_DOMAIN, ID_DETECT, ID_DC, ID_ADMIN, ID_PASS, ID_USER, ID_SEARCH, ID_OU,
    ID_LOADOU, ID_SIM, ID_RUN, ID_LOG, ID_PROG, ID_USERSTATUS, ID_HEADER, ID_EXPORT, ID_IMPORT, ID_UNDO, ID_REPAIR, ID_CHK0 = 300
};

enum Msg {
    WM_LOG = WM_APP + 1, WM_SIZE_RES, WM_DC_RES, WM_USERS_RES, WM_OUS_RES, WM_DONE
};

struct UsersResult {
    std::vector<AdUser> users;
    std::string error;
};
struct OusResult {
    std::vector<std::string> ous;
    std::string error;
};

struct CheckDef {
    const wchar_t* text;
    bool Options::*field;
};

const CheckDef kChecks[] = {
    {L"Unir el equipo al dominio destino", &Options::join},
    {L"Respaldar registro (permite rollback)", &Options::backup},
    {L"Limpiar credenciales y Vault viejos", &Options::creds},
    {L"Archivar .ost de Outlook", &Options::ost},
    {L"Borrar tokens Office / Entra ID", &Options::m365},
    {L"Limpiar cachés de iconos y miniaturas", &Options::icons},
    {L"Quitar directivas del dominio anterior", &Options::policies},
    {L"Normalizar carpetas (quitar redirección)", &Options::shell},
    {L"Re-registrar apps al 1.er inicio (experimental)", &Options::runonce},
    {L"Preseleccionar usuario en el login", &Options::default_logon},
    {L"Purgar Kerberos y caché DNS", &Options::net_hygiene},
    {L"Añadir a Administradores locales", &Options::add_admin},
    {L"Suspender BitLocker (1 reinicio)", &Options::bitlocker},
    {L"Crear punto de restauración", &Options::restore_point},
    {L"Borrar GPO local (afecta a todo el equipo)", &Options::purge_gpo},
};
constexpr int kNumChecks = sizeof(kChecks) / sizeof(kChecks[0]);

struct App {
    HINSTANCE inst = nullptr;
    HWND wnd = nullptr, lv = nullptr, domain = nullptr, dc = nullptr, admin = nullptr, pass = nullptr, user = nullptr,
         ou = nullptr, user_status = nullptr, log = nullptr, prog = nullptr, sim = nullptr, run = nullptr,
         refresh = nullptr, sizes = nullptr, detect = nullptr, search = nullptr, loadou = nullptr,
         exportb = nullptr, importb = nullptr, undob = nullptr, repairb = nullptr;
    HWND checks[kNumChecks] = {};
    HFONT font = nullptr, mono = nullptr;
    int dpi = 96;
    std::vector<Profile> profiles;
    std::vector<AdUser> found;
    std::string chosen_sam;
    std::atomic<bool> busy{false};
    std::atomic<bool> sizing{false};
} g;

int S(int v) { return MulDiv(v, g.dpi, 96); }

HWND make(const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id = 0,
          DWORD ex = 0) {
    return CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, S(x), S(y), S(w), S(h), g.wnd,
                           (HMENU)(INT_PTR)id, g.inst, nullptr);
}

HWND label(const wchar_t* text, int x, int y, int w) { return make(L"STATIC", text, SS_LEFT, x, y + 3, w, 18); }
HWND edit(int x, int y, int w, int id, DWORD extra = 0) {
    return make(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | extra, x, y, w, 23, id, WS_EX_CLIENTEDGE);
}
HWND button(const wchar_t* text, int x, int y, int w, int h, int id, DWORD extra = 0) {
    return make(L"BUTTON", text, WS_TABSTOP | BS_PUSHBUTTON | extra, x, y, w, h, id);
}

std::string get_text(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring w(n + 1, L'\0');
    GetWindowTextW(h, w.data(), n + 1);
    w.resize(n);
    return narrow(w);
}

void set_text(HWND h, const std::string& s) { SetWindowTextW(h, widen(s).c_str()); }

std::string human_size(unsigned long long b) {
    const char* u[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)b;
    int i = 0;
    while (v >= 1024 && i < 4) v /= 1024, ++i;
    char buf[32];
    std::snprintf(buf, sizeof buf, i == 0 ? "%.0f %s" : "%.1f %s", v, u[i]);
    return buf;
}

unsigned long long dir_size(const std::wstring& dir) {
    unsigned long long total = 0;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) total += dir_size(dir + L"\\" + n);
        else total += ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return total;
}

void append_log(const std::wstring& w) {
    std::wstring s;
    s.reserve(w.size() + 8);
    for (size_t i = 0; i < w.size(); ++i) {
        if (w[i] == L'\n' && (i == 0 || w[i - 1] != L'\r')) s += L'\r';
        s += w[i];
    }
    SendMessageW(g.log, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g.log, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
}

void ui_log(const std::string& s) { append_log(widen(s) + L"\n"); }

void set_busy(bool b) {
    g.busy = b;
    for (HWND h : {g.sim, g.run, g.refresh, g.detect, g.search, g.loadou, g.exportb, g.importb, g.undob, g.repairb})
        EnableWindow(h, !b);
    SendMessageW(g.prog, PBM_SETMARQUEE, b ? TRUE : FALSE, 30);
    ShowWindow(g.prog, b ? SW_SHOW : SW_HIDE);
}

void fill_profiles() {
    g.profiles = list_profiles();
    ListView_DeleteAllItems(g.lv);
    for (size_t i = 0; i < g.profiles.size(); ++i) {
        const Profile& p = g.profiles[i];
        std::wstring acct = widen(p.account);
        LVITEMW it{};
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = acct.data();
        ListView_InsertItem(g.lv, &it);
        ListView_SetItemText(g.lv, (int)i, 1, const_cast<LPWSTR>(p.path.c_str()));
        ListView_SetItemText(g.lv, (int)i, 2, const_cast<LPWSTR>(L"-"));
        const wchar_t* st = p.loaded ? L"SESIÓN ACTIVA" : (p.exists ? L"Disponible" : L"Sin carpeta");
        ListView_SetItemText(g.lv, (int)i, 3, const_cast<LPWSTR>(st));
    }
}

struct Gathered {
    Options o;
    bool ok = false;
};

// Perfil seleccionado en la lista, o nullptr (avisando al usuario) si no hay uno utilizable.
const Profile* selected_profile() {
    int sel = ListView_GetNextItem(g.lv, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g.profiles.size()) {
        MessageBoxW(g.wnd, L"Selecciona un perfil local de la lista.", L"Falta el perfil", MB_ICONWARNING);
        return nullptr;
    }
    const Profile& p = g.profiles[sel];
    if (p.loaded) {
        MessageBoxW(g.wnd,
                    L"Ese perfil tiene la sesión abierta. Cierra la sesión de ese usuario (o inicia con otro "
                    L"administrador local) e inténtalo de nuevo.",
                    L"Perfil en uso", MB_ICONWARNING);
        return nullptr;
    }
    return &p;
}

// Reúne las opciones de la ventana. Con `import_zip` no se necesita un perfil seleccionado.
Gathered gather(bool dry, const std::string& import_zip = "") {
    Gathered r;
    Options& o = r.o;
    if (import_zip.empty()) {
        const Profile* p = selected_profile();
        if (!p) return r;
        o.profile = narrow(p->path);
    } else {
        o.import_zip = import_zip;
    }
    o.domain = get_text(g.domain);
    o.dc = get_text(g.dc);
    o.admin = get_text(g.admin);
    o.password = get_text(g.pass);
    o.user = g.chosen_sam.empty() ? get_text(g.user) : g.chosen_sam;
    int ou = (int)SendMessageW(g.ou, CB_GETCURSEL, 0, 0);
    if (ou > 0) {
        wchar_t buf[512];
        SendMessageW(g.ou, CB_GETLBTEXT, ou, (LPARAM)buf);
        o.ou = narrow(buf);
    }
    for (int i = 0; i < kNumChecks; ++i)
        o.*(kChecks[i].field) = SendMessageW(g.checks[i], BM_GETCHECK, 0, 0) == BST_CHECKED;
    o.dry = dry;
    if (o.domain.empty() || o.dc.empty() || o.admin.empty() || o.password.empty() || o.user.empty()) {
        MessageBoxW(g.wnd, L"Completa dominio, controlador de dominio, administrador, contraseña y usuario destino.",
                    L"Faltan datos", MB_ICONWARNING);
        return r;
    }
    r.ok = true;
    return r;
}

// Si UCPD está cargado, ofrece desactivarlo (hay que reiniciar). Devuelve true si la operación debe cancelarse.
bool offer_disable_ucpd() {
    UcpdInfo u = ucpd_query();
    if (!u.present || !u.running) return false;
    std::wstring msg =
        L"UCPD (la protección de aplicaciones predeterminadas de Windows) está activo.\n\n"
        L"Impide borrar las asociaciones de archivos inválidas (http, https y .pdf) del perfil. Si se continúa así, Edge "
        L"intentará repararlas sin parar y los iconos del usuario parpadearán.\n\n"
        L"Sí: desactivar UCPD ahora. Hay que reiniciar y volver a ejecutar la operación; profmig lo restaura solo al "
        L"terminar con éxito.\n"
        L"No: continuar sin desactivarlo (no recomendado).\n"
        L"Cancelar: no hacer nada.";
    int r = MessageBoxW(g.wnd, msg.c_str(), L"UCPD activo", MB_ICONWARNING | MB_YESNOCANCEL | MB_DEFBUTTON1);
    if (r == IDCANCEL) return true;
    if (r == IDNO) return false;
    try {
        ucpd_disable();
    } catch (const std::exception& e) {
        MessageBoxW(g.wnd, (L"No se pudo desactivar UCPD:\n\n" + widen(e.what())).c_str(), L"UCPD", MB_ICONERROR);
        return true;
    }
    if (MessageBoxW(g.wnd,
                    L"UCPD desactivado. Hay que reiniciar el equipo para que surta efecto y después volver a ejecutar la "
                    L"operación.\n\n¿Reiniciar ahora?",
                    L"profmig", MB_ICONQUESTION | MB_YESNO) == IDYES)
        run(L"shutdown.exe /r /t 15 /c \"profmig: reinicio tras desactivar UCPD\"");
    return true;
}

// Resultado de una operación larga, enviado al hilo de la interfaz.
struct Done {
    std::string error;
    std::wstring success_message;  // vacío = mensaje por defecto de simulación
    bool offer_reboot = false;
};

// Ejecuta `job` en un hilo, con la interfaz bloqueada y el registro limpio.
void run_async(std::function<int()> job, std::wstring success_message, bool offer_reboot) {
    SetWindowTextW(g.log, L"");
    set_busy(true);
    HWND wnd = g.wnd;
    std::thread([job, wnd, success_message, offer_reboot] {
        int rc = 1;
        auto* d = new Done{"", success_message, offer_reboot};
        try {
            rc = job();
        } catch (const std::exception& e) {
            d->error = e.what();
            warn("ERROR: " + d->error);
        }
        PostMessageW(wnd, WM_DONE, (WPARAM)rc, (LPARAM)d);
    }).detach();
}

void start_migration(bool dry, const std::string& import_zip = "") {
    Gathered gr = gather(dry, import_zip);
    if (!gr.ok) return;
    const bool importing = !import_zip.empty();
    if (!dry && offer_disable_ucpd()) return;
    if (!dry) {
        std::wstring what = importing ? L"Se va a importar el perfil\n\n" + widen(import_zip)
                                      : L"Se va a migrar el perfil\n\n" + widen(gr.o.profile);
        std::wstring msg = what + L"\n\nal usuario " + widen(gr.o.domain + "\\" + bare_user(gr.o.user)) +
                           L".\n\nSe modificarán el registro y los permisos del perfil y se borrarán credenciales "
                           L"guardadas. Se hará un respaldo del registro, pero los permisos NTFS no se pueden "
                           L"revertir (sí se puede usar «Deshacer última»).\n\n¿Continuar? (Recomendado: ejecuta antes una "
                           L"simulación.)";
        if (MessageBoxW(g.wnd, msg.c_str(), L"Confirmar", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) return;
    }
    Options o = gr.o;
    run_async([o] { return run_migration(o, nullptr); }, L"", !o.dry);
}

std::wstring file_dialog(bool save, const wchar_t* title, const wchar_t* default_name) {
    wchar_t file[MAX_PATH] = {};
    if (default_name) wcsncpy(file, default_name, MAX_PATH - 1);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = g.wnd;
    ofn.lpstrFilter = L"Perfil exportado (*.zip)\0*.zip\0Todos los archivos\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.lpstrDefExt = L"zip";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    BOOL ok = save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
    return ok ? std::wstring(file) : L"";
}

void start_export() {
    const Profile* p = selected_profile();
    if (!p) return;
    std::wstring def = L"perfil_" + p->path.substr(p->path.find_last_of(L'\\') + 1) + L".zip";
    std::wstring zip = file_dialog(true, L"Exportar perfil a .zip", def.c_str());
    if (zip.empty()) return;
    std::string profile = narrow(p->path), out = narrow(zip);
    run_async([profile, out] { return run_export(profile, out); }, L"Perfil exportado correctamente:\n\n" + zip, false);
}

void start_import(bool dry) {
    std::wstring zip = file_dialog(false, L"Importar perfil desde .zip", nullptr);
    if (zip.empty()) return;
    start_migration(dry, narrow(zip));
}

void start_undo() {
    auto last = journal_last();
    if (!last) {
        MessageBoxW(g.wnd, L"No hay ninguna migración registrada que se pueda deshacer.", L"Deshacer",
                    MB_ICONINFORMATION);
        return;
    }
    std::wstring msg = L"Última migración registrada:\n\n" + widen(last->account) + L"  →  " + widen(last->domain) + L"\\" +
                       widen(last->user) + L"\n" + last->path +
                       L"\n\nSe restaurará el registro y se devolverán la propiedad y los permisos de la carpeta al usuario "
                       L"original.\nNo se restauran las credenciales borradas ni se saca el equipo del dominio.\n\n"
                       L"¿Deshacer?";
    if (MessageBoxW(g.wnd, msg.c_str(), L"Deshacer última migración", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
        return;
    run_async([] { return run_undo(nullptr); }, L"Migración deshecha. Ya puede volver a iniciarse sesión con el usuario original.",
              false);
}

void start_repair() {
    const Profile* p = selected_profile();
    if (!p) return;
    if (offer_disable_ucpd()) return;
    std::wstring msg = L"Se reparará el perfil seleccionado:\n\n" + widen(p->account) + L"\n" + p->path +
                       L"\n\nSe revisarán los permisos de las carpetas y las claves del registro: el SID anterior (se detecta "
                       L"solo en el propio perfil) se sustituirá por el actual y se borrarán las asociaciones de archivos "
                       L"inválidas (UserChoice) que hacen que Edge provoque el parpadeo de iconos.\n\nEl usuario NO debe tener "
                       L"la sesión iniciada. Si Windows tiene activo UCPD, esas claves no se podrán borrar (el registro lo "
                       L"indicará).\n\n¿Reparar?";
    if (MessageBoxW(g.wnd, msg.c_str(), L"Reparar perfil migrado", MB_ICONQUESTION | MB_YESNO) != IDYES) return;
    std::string folder = narrow(p->path);
    run_async([folder] { return run_fixsid(folder, "", "", false); },
              L"Reparación terminada. Revisa el registro de abajo: las líneas \"con error\" deben ser 0.", false);
}

void start_sizes() {
    if (g.sizing.exchange(true)) return;
    std::vector<std::wstring> paths;
    for (auto& p : g.profiles) paths.push_back(p.exists ? p.path : L"");
    HWND wnd = g.wnd;
    std::thread([paths, wnd] {
        for (size_t i = 0; i < paths.size(); ++i) {
            unsigned long long sz = paths[i].empty() ? 0 : dir_size(paths[i]);
            PostMessageW(wnd, WM_SIZE_RES, (WPARAM)i, (LPARAM)sz);
        }
        PostMessageW(wnd, WM_SIZE_RES, (WPARAM)-1, 0);
    }).detach();
}

bool need_creds() {
    if (get_text(g.dc).empty() || get_text(g.domain).empty() || get_text(g.admin).empty() || get_text(g.pass).empty()) {
        MessageBoxW(g.wnd,
                    L"Para consultar el dominio indica dominio, controlador de dominio, administrador y contraseña.",
                    L"Faltan credenciales", MB_ICONWARNING);
        return false;
    }
    return true;
}

void on_command(int id, int code) {
    switch (id) {
        case ID_REFRESH: fill_profiles(); break;
        case ID_SIZES: start_sizes(); break;
        case ID_DETECT: {
            std::string d = get_text(g.domain);
            if (d.empty()) {
                MessageBoxW(g.wnd, L"Escribe primero el dominio.", L"Dominio", MB_ICONINFORMATION);
                break;
            }
            ui_log("Buscando un controlador de dominio para " + d + "...");
            HWND wnd = g.wnd;
            std::thread([d, wnd] { PostMessageW(wnd, WM_DC_RES, 0, (LPARAM) new std::string(discover_dc(d))); }).detach();
            break;
        }
        case ID_SEARCH: {
            if (!need_creds()) break;
            std::string dc = get_text(g.dc), dom = get_text(g.domain), adm = get_text(g.admin), pw = get_text(g.pass);
            std::string q = get_text(g.user);
            if (!g.chosen_sam.empty()) q = g.chosen_sam;
            set_text(g.user_status, "Consultando Active Directory...");
            HWND wnd = g.wnd;
            std::thread([=] {
                auto* r = new UsersResult;
                try {
                    r->users = ad_find_users(dc, dom, adm, pw, q);
                } catch (const std::exception& e) {
                    r->error = e.what();
                }
                PostMessageW(wnd, WM_USERS_RES, 0, (LPARAM)r);
            }).detach();
            break;
        }
        case ID_LOADOU: {
            if (!need_creds()) break;
            std::string dc = get_text(g.dc), dom = get_text(g.domain), adm = get_text(g.admin), pw = get_text(g.pass);
            HWND wnd = g.wnd;
            std::thread([=] {
                auto* r = new OusResult;
                try {
                    r->ous = ad_list_ous(dc, dom, adm, pw);
                } catch (const std::exception& e) {
                    r->error = e.what();
                }
                PostMessageW(wnd, WM_OUS_RES, 0, (LPARAM)r);
            }).detach();
            break;
        }
        case ID_USER:
            if (code == CBN_EDITCHANGE) {
                g.chosen_sam.clear();
            } else if (code == CBN_SELCHANGE) {
                int i = (int)SendMessageW(g.user, CB_GETCURSEL, 0, 0);
                if (i >= 0 && i < (int)g.found.size()) {
                    const AdUser& u = g.found[i];
                    g.chosen_sam = u.sam;
                    set_text(g.user_status, (u.enabled ? "OK  " : "ATENCIÓN  ") + u.display + "  |  " + u.status +
                                                "  |  SID " + u.sid);
                }
            }
            break;
        case ID_SIM: start_migration(true); break;
        case ID_RUN: start_migration(false); break;
        case ID_EXPORT: start_export(); break;
        case ID_IMPORT: start_import(false); break;
        case ID_UNDO: start_undo(); break;
        case ID_REPAIR: start_repair(); break;
    }
}

void on_message_users(UsersResult* r) {
    g.found = r->users;
    SendMessageW(g.user, CB_RESETCONTENT, 0, 0);
    g.chosen_sam.clear();
    if (!r->error.empty()) {
        set_text(g.user_status, "Error: " + r->error);
        ui_log("Consulta LDAP fallida: " + r->error);
    } else if (r->users.empty()) {
        set_text(g.user_status, "No se encontraron usuarios con ese criterio.");
    } else {
        for (auto& u : r->users) {
            std::string line = u.sam + "  —  " + u.display + (u.mail.empty() ? "" : "  <" + u.mail + ">") +
                               (u.enabled ? "" : "  [DESHABILITADA]");
            SendMessageW(g.user, CB_ADDSTRING, 0, (LPARAM)widen(line).c_str());
        }
        set_text(g.user_status, std::to_string(r->users.size()) + " usuario(s). Elige uno de la lista.");
        if (r->users.size() == 1) {
            SendMessageW(g.user, CB_SETCURSEL, 0, 0);
            on_command(ID_USER, CBN_SELCHANGE);
        } else {
            SendMessageW(g.user, CB_SHOWDROPDOWN, TRUE, 0);
        }
    }
    delete r;
}

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_COMMAND: on_command(LOWORD(wp), HIWORD(wp)); return 0;
        case WM_LOG: {
            auto* w = (std::wstring*)lp;
            append_log(*w);
            delete w;
            return 0;
        }
        case WM_SIZE_RES: {
            if ((int)wp < 0) {
                g.sizing = false;
                return 0;
            }
            std::string s = human_size((unsigned long long)lp);
            ListView_SetItemText(g.lv, (int)wp, 2, const_cast<LPWSTR>(widen(s).c_str()));
            return 0;
        }
        case WM_DC_RES: {
            auto* s = (std::string*)lp;
            if (s->empty()) {
                ui_log("No se encontró un DC. Revisa que el DNS del equipo apunte al dominio, o escríbelo a mano.");
            } else {
                set_text(g.dc, *s);
                ui_log("DC encontrado: " + *s);
            }
            delete s;
            return 0;
        }
        case WM_USERS_RES: on_message_users((UsersResult*)lp); return 0;
        case WM_OUS_RES: {
            auto* r = (OusResult*)lp;
            if (!r->error.empty()) {
                ui_log("No se pudieron leer las OUs: " + r->error);
            } else {
                SendMessageW(g.ou, CB_RESETCONTENT, 0, 0);
                SendMessageW(g.ou, CB_ADDSTRING, 0, (LPARAM)L"(Contenedor Computers por defecto)");
                for (auto& o : r->ous) SendMessageW(g.ou, CB_ADDSTRING, 0, (LPARAM)widen(o).c_str());
                SendMessageW(g.ou, CB_SETCURSEL, 0, 0);
                ui_log(std::to_string(r->ous.size()) + " OU(s) cargadas.");
            }
            delete r;
            return 0;
        }
        case WM_DONE: {
            std::unique_ptr<Done> d((Done*)lp);
            std::string err = d->error;
            set_busy(false);
            fill_profiles();
            if ((int)wp == 0 && !d->success_message.empty()) {
                MessageBoxW(hwnd, d->success_message.c_str(), L"profmig", MB_ICONINFORMATION);
            } else if ((int)wp == 0 && d->offer_reboot) {
                if (MessageBoxW(hwnd,
                                L"Migración completada.\n\nHay que reiniciar para terminar la unión al dominio e iniciar "
                                L"sesión con el usuario nuevo.\n\n¿Reiniciar ahora?",
                                L"profmig", MB_ICONINFORMATION | MB_YESNO) == IDYES)
                    run(L"shutdown.exe /r /t 10 /c \"profmig: migracion completada\"");
            } else if ((int)wp == 0) {
                MessageBoxW(hwnd, L"Simulación correcta: la validación pasó y no se modificó nada.", L"profmig",
                            MB_ICONINFORMATION);
            } else {
                std::wstring m = L"La operación no se completó. Revisa el registro de abajo.";
                if (!err.empty()) m += L"\n\n" + widen(err);
                MessageBoxW(hwnd, m.c_str(), L"profmig", MB_ICONERROR);
            }
            return 0;
        }
        case WM_CLOSE:
            if (g.busy) {
                MessageBoxW(hwnd, L"Hay una operación en curso. Espera a que termine para no dejar el perfil a medias.",
                            L"profmig", MB_ICONWARNING);
                return 0;
            }
            if (ucpd_disabled_by_profmig()) {
                int r = MessageBoxW(hwnd,
                                    L"UCPD sigue desactivado por profmig (lo dejaste así para migrar o reparar).\n\n"
                                    L"Sí: restaurarlo ahora y cerrar.\nNo: cerrar dejándolo desactivado (se restaurará al terminar "
                                    L"la próxima operación).\nCancelar: no cerrar.",
                                    L"UCPD", MB_ICONQUESTION | MB_YESNOCANCEL | MB_DEFBUTTON2);
                if (r == IDCANCEL) return 0;
                if (r == IDYES) {
                    try {
                        ucpd_restore();
                    } catch (const std::exception& e) {
                        MessageBoxW(hwnd, (L"No se pudo restaurar UCPD:\n\n" + widen(e.what())).c_str(), L"UCPD", MB_ICONERROR);
                        return 0;
                    }
                }
            }
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

BOOL CALLBACK set_font_cb(HWND h, LPARAM) {
    SendMessageW(h, WM_SETFONT, (WPARAM)g.font, TRUE);
    return TRUE;
}

void build_ui() {
    // Cabecera
    std::wstring comp = L"Equipo";
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(name, &n)) comp = name;
    std::string dom = current_domain();
    std::wstring head = L"Equipo: " + comp + L"    |    Dominio actual: " +
                        (dom.empty() ? std::wstring(L"(grupo de trabajo)") : widen(dom));
    make(L"STATIC", head.c_str(), SS_LEFT, 12, 8, 876, 18, ID_HEADER);

    // 1. Perfil
    make(L"BUTTON", L" 1. Perfil local a migrar ", BS_GROUPBOX, 8, 30, 884, 188);
    g.lv = make(WC_LISTVIEWW, L"", WS_TABSTOP | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 18, 50,
                864, 126, ID_LV);
    ListView_SetExtendedListViewStyle(g.lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    struct Col {
        const wchar_t* t;
        int w;
    } cols[] = {{L"Cuenta", 200}, {L"Carpeta", 340}, {L"Tamaño", 90}, {L"Estado", 215}};
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH;
        c.pszText = const_cast<LPWSTR>(cols[i].t);
        c.cx = S(cols[i].w);
        ListView_InsertColumn(g.lv, i, &c);
    }
    g.refresh = button(L"Actualizar", 18, 184, 110, 26, ID_REFRESH);
    g.sizes = button(L"Calcular tamaños", 136, 184, 140, 26, ID_SIZES);
    g.exportb = button(L"Exportar a .zip…", 284, 184, 140, 26, ID_EXPORT);

    // 2. Dominio
    make(L"BUTTON", L" 2. Dominio destino ", BS_GROUPBOX, 8, 224, 884, 154);
    label(L"Dominio", 20, 248, 90);
    g.domain = edit(112, 246, 250, ID_DOMAIN);
    g.detect = button(L"Detectar DC", 368, 245, 100, 25, ID_DETECT);
    label(L"Controlador (DC)", 488, 248, 100);
    g.dc = edit(592, 246, 288, ID_DC);

    label(L"Administrador", 20, 280, 90);
    g.admin = edit(112, 278, 250, ID_ADMIN);
    label(L"Contraseña", 488, 280, 100);
    g.pass = edit(592, 278, 288, ID_PASS, ES_PASSWORD);

    label(L"Usuario destino", 20, 312, 90);
    g.user = make(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN | CBS_AUTOHSCROLL, 112, 310, 250, 220, ID_USER);
    g.search = button(L"Buscar en AD", 368, 309, 100, 25, ID_SEARCH);
    label(L"OU del equipo", 488, 312, 100);
    g.ou = make(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, 592, 310, 208, 220, ID_OU);
    SendMessageW(g.ou, CB_ADDSTRING, 0, (LPARAM)L"(Contenedor Computers por defecto)");
    SendMessageW(g.ou, CB_SETCURSEL, 0, 0);
    g.loadou = button(L"Cargar OUs", 806, 309, 74, 25, ID_LOADOU);

    g.user_status = make(L"STATIC", L"Escribe parte del usuario, nombre o correo y pulsa \"Buscar en AD\".",
                         SS_LEFT | SS_ENDELLIPSIS, 112, 344, 768, 18, ID_USERSTATUS);

    // 3. Opciones
    make(L"BUTTON", L" 3. Opciones ", BS_GROUPBOX, 8, 384, 884, 140);
    Options defaults;
    for (int i = 0; i < kNumChecks; ++i) {
        int col = i / 5, row = i % 5;
        g.checks[i] = make(L"BUTTON", kChecks[i].text, WS_TABSTOP | BS_AUTOCHECKBOX, 20 + col * 292, 404 + row * 22,
                           284, 20, ID_CHK0 + i);
        SendMessageW(g.checks[i], BM_SETCHECK, defaults.*(kChecks[i].field) ? BST_CHECKED : BST_UNCHECKED, 0);
    }

    // Acciones
    g.sim = button(L"Simular (sin cambios)", 8, 534, 170, 34, ID_SIM);
    g.run = button(L"Migrar perfil", 184, 534, 130, 34, ID_RUN, BS_DEFPUSHBUTTON);
    g.importb = button(L"Importar .zip…", 330, 534, 130, 34, ID_IMPORT);
    g.undob = button(L"Deshacer última", 466, 534, 130, 34, ID_UNDO);
    g.repairb = button(L"Reparar seleccionado", 602, 534, 130, 34, ID_REPAIR);
    g.prog = make(PROGRESS_CLASSW, L"", PBS_MARQUEE, 744, 544, 148, 16, ID_PROG);
    ShowWindow(g.prog, SW_HIDE);

    // Registro
    g.log = make(L"EDIT", L"", WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 8, 578, 884, 134, ID_LOG,
                 WS_EX_CLIENTEDGE);
    SendMessageW(g.log, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);

    EnumChildWindows(g.wnd, set_font_cb, 0);
    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(9, g.dpi, 72);
    lf.lfCharSet = DEFAULT_CHARSET;
    wcscpy(lf.lfFaceName, L"Consolas");
    g.mono = CreateFontIndirectW(&lf);
    SendMessageW(g.log, WM_SETFONT, (WPARAM)g.mono, TRUE);
}

}  // namespace

int run_gui(HINSTANCE inst) {
    // PROFMIG_PREVIEW=1: permite abrir la interfaz sin elevar (solo para ver la UI; migrar seguira exigiendo admin)
    if (!is_admin() && !GetEnvironmentVariableW(L"PROFMIG_PREVIEW", nullptr, 0)) {
        wchar_t exe[MAX_PATH];
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        auto r = (INT_PTR)ShellExecuteW(nullptr, L"runas", exe, nullptr, nullptr, SW_SHOWNORMAL);
        if (r <= 32) MessageBoxW(nullptr, L"profmig necesita permisos de Administrador.", L"profmig", MB_ICONERROR);
        return r > 32 ? 0 : 1;
    }

    INITCOMMONCONTROLSEX icc{sizeof icc, ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    g.inst = inst;
    g.dpi = (int)GetDpiForSystem();

    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof ncm;
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
    g.font = CreateFontIndirectW(&ncm.lfMessageFont);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ProfMigWnd";
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT rc{0, 0, S(900), S(720)};
    AdjustWindowRectEx(&rc, style, FALSE, WS_EX_CONTROLPARENT);
    const std::wstring title = L"profmig " + widen(PROFMIG_VERSION) + L" — Migración de perfiles a dominio";
    g.wnd = CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName, title.c_str(), style,
                            CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr,
                            inst, nullptr);
    build_ui();
    fill_profiles();

    HWND wnd = g.wnd;
    set_log_sink([wnd](const std::string& line) {
        PostMessageW(wnd, WM_LOG, 0, (LPARAM) new std::wstring(widen(line)));
    });
    ui_log("Listo. Selecciona un perfil, rellena el dominio y pulsa \"Simular\" antes de migrar.");
    {
        UcpdInfo u = ucpd_query();
        if (u.present && u.running)
            ui_log("Aviso: UCPD está activo. Al migrar o reparar, profmig te ofrecerá desactivarlo (hay que reiniciar).");
        else if (u.present && ucpd_disabled_by_profmig())
            ui_log("UCPD está desactivado por profmig: se restaurará solo al terminar la migración o la reparación.");
    }

    ShowWindow(g.wnd, SW_SHOW);
    UpdateWindow(g.wnd);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(g.wnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}

}  // namespace pm
