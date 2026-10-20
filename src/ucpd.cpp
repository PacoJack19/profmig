#include "ucpd.hpp"

#include <winsvc.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <vector>

#include "util.hpp"

namespace pm {

namespace {

const wchar_t* kStateFile = L"C:\\ProfMig\\ucpd_state.txt";
const wchar_t* kTask = L"\\Microsoft\\Windows\\AppxDeploymentClient\\UCPD velocity";
const wchar_t* kServiceKey = L"SYSTEM\\CurrentControlSet\\Services\\UCPD";

// La salida de schtasks /XML puede venir en UTF-16: se quitan los NUL para buscar en texto plano.
bool task_enabled(bool* known) {
    std::string out;
    int rc = run(std::wstring(L"schtasks.exe /Query /TN \"") + kTask + L"\" /XML", &out);
    out.erase(std::remove(out.begin(), out.end(), '\0'), out.end());
    if (rc != 0 || out.find("<Task") == std::string::npos) {
        *known = false;
        return true;
    }
    *known = true;
    return out.find("<Enabled>false</Enabled>") == std::string::npos;
}

bool set_task(bool enable) {
    std::string out;
    int rc = run(std::wstring(L"schtasks.exe /Change /TN \"") + kTask + L"\" " + (enable ? L"/ENABLE" : L"/DISABLE"), &out);
    return rc == 0;
}

// Cambia el tipo de inicio: primero por el administrador de servicios y, si el servicio no lo permite, por el registro.
bool set_start_type(DWORD type, std::string& err) {
    bool ok = false;
    if (SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)) {
        if (SC_HANDLE svc = OpenServiceW(scm, L"UCPD", SERVICE_CHANGE_CONFIG)) {
            ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, type, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr,
                                      nullptr, nullptr, nullptr) != 0;
            if (!ok) err = "ChangeServiceConfig: " + win_error(GetLastError());
            CloseServiceHandle(svc);
        } else {
            err = "OpenService: " + win_error(GetLastError());
        }
        CloseServiceHandle(scm);
    }
    if (ok) return true;

    HKEY k = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kServiceKey, 0, KEY_SET_VALUE, &k);
    if (rc == ERROR_SUCCESS) {
        rc = RegSetValueExW(k, L"Start", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&type), sizeof type);
        RegCloseKey(k);
        if (rc == ERROR_SUCCESS) return true;
    }
    err += " / registro: " + win_error((DWORD)rc);
    return false;
}

std::map<std::string, std::string> read_state() {
    std::map<std::string, std::string> kv;
    std::ifstream f(std::filesystem::path(kStateFile), std::ios::binary);
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos) kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return kv;
}

}  // namespace

UcpdInfo ucpd_query() {
    UcpdInfo i;
    if (SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)) {
        if (SC_HANDLE svc = OpenServiceW(scm, L"UCPD", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)) {
            i.present = true;
            SERVICE_STATUS st{};
            if (QueryServiceStatus(svc, &st)) i.running = st.dwCurrentState == SERVICE_RUNNING;
            DWORD need = 0;
            QueryServiceConfigW(svc, nullptr, 0, &need);
            if (need) {
                std::vector<BYTE> buf(need);
                if (QueryServiceConfigW(svc, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data()), need, &need))
                    i.start_type = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data())->dwStartType;
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    if (i.present) i.task_enabled = task_enabled(&i.task_known);
    return i;
}

bool ucpd_disabled_by_profmig() {
    std::error_code ec;
    return std::filesystem::exists(kStateFile, ec);
}

void ucpd_disable() {
    if (!is_admin()) throw Fail("Desactivar UCPD requiere permisos de Administrador.");
    UcpdInfo cur = ucpd_query();
    if (!cur.present) throw Fail("Este Windows no tiene el servicio UCPD: no hay nada que desactivar.");
    if (ucpd_disabled_by_profmig()) {
        info("UCPD ya lo desactivo profmig antes; se conserva el estado original guardado.");
        return;
    }

    // El estado original se guarda ANTES de cambiar nada, para poder restaurar aunque algo falle a medias
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(kStateFile).parent_path(), ec);
    {
        std::ofstream f(std::filesystem::path(kStateFile), std::ios::binary | std::ios::trunc);
        if (!f) throw Fail("No se pudo guardar el estado de UCPD en C:\\ProfMig.");
        f << "orig_start=" << cur.start_type << "\norig_task_enabled=" << (cur.task_enabled ? 1 : 0)
          << "\ntask_known=" << (cur.task_known ? 1 : 0) << "\n";
    }

    std::string err;
    if (!set_start_type(SERVICE_DISABLED, err)) {
        std::filesystem::remove(kStateFile, ec);
        throw Fail("No se pudo desactivar el servicio UCPD: " + err);
    }
    if (cur.task_known && cur.task_enabled && !set_task(false))
        warn("No se pudo desactivar la tarea programada 'UCPD velocity'; podria reactivar el servicio.");
    ok("UCPD desactivado. Surte efecto al REINICIAR el equipo; despues ejecuta de nuevo la operacion.");
}

bool ucpd_restore() {
    if (!ucpd_disabled_by_profmig()) return false;
    if (!is_admin()) throw Fail("Restaurar UCPD requiere permisos de Administrador.");
    auto kv = read_state();
    // Tipo de inicio original; si por lo que sea no consta, el que trae Windows (inicio del sistema).
    // Si ya estaba desactivado antes de que actuara profmig (4), se respeta: se deja desactivado.
    DWORD start = kv.count("orig_start") ? (DWORD)std::strtoul(kv["orig_start"].c_str(), nullptr, 10) : SERVICE_SYSTEM_START;

    std::string err;
    if (!set_start_type(start, err)) throw Fail("No se pudo restaurar el servicio UCPD: " + err);
    if (kv["task_known"] == "1" && kv["orig_task_enabled"] == "1" && !set_task(true))
        warn("No se pudo reactivar la tarea programada 'UCPD velocity'.");

    std::error_code ec;
    std::filesystem::remove(kStateFile, ec);
    ok("UCPD restaurado a su estado original (volvera a estar activo tras reiniciar).");
    return true;
}

}  // namespace pm
