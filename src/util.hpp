#pragma once
#include <windows.h>
#include <stdexcept>
#include <functional>
#include <string>

namespace pm {

struct Fail : std::runtime_error {
    using std::runtime_error::runtime_error;
};

extern bool g_dry;  // --dry-run: las operaciones que modifican el sistema solo se anuncian

std::wstring widen(const std::string& s);
std::string narrow(const std::wstring& s);
std::string win_error(DWORD code);

void log_open(const std::wstring& path);
// Receptor adicional de cada linea de log (la GUI lo usa para mostrarlas). Se llama desde cualquier hilo.
void set_log_sink(std::function<void(const std::string&)> sink);
void log_line(const char* tag, const std::string& msg);
inline void info(const std::string& m) { log_line("*", m); }
inline void ok(const std::string& m) { log_line("+", m); }
inline void warn(const std::string& m) { log_line("!", m); }
inline void dry(const std::string& m) { log_line("dry", m); }

bool is_admin();
bool enable_privilege(const wchar_t* name);

// Ejecuta una línea de comandos sin shell. Devuelve el código de salida (o -1 si no arrancó).
int run(const std::wstring& cmdline, std::string* output = nullptr, DWORD timeout_ms = 600000);

std::string read_secret(const std::string& prompt);

}  // namespace pm
