#include "util.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace pm {

bool g_dry = false;
static std::ofstream g_log;
static std::function<void(const std::string&)> g_sink;

void set_log_sink(std::function<void(const std::string&)> sink) { g_sink = std::move(sink); }

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::string win_error(DWORD code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring msg = n ? std::wstring(buf, n) : L"";
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' || msg.back() == L' ')) msg.pop_back();
    return "[" + std::to_string(code) + "] " + narrow(msg);
}

void log_open(const std::wstring& path) {
    std::filesystem::path p(path);
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    g_log.open(p, std::ios::binary | std::ios::app);
}

void log_line(const char* tag, const std::string& msg) {
    SYSTEMTIME t;
    GetLocalTime(&t);
    char head[64];
    std::snprintf(head, sizeof head, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ", t.wYear, t.wMonth, t.wDay, t.wHour,
                  t.wMinute, t.wSecond, tag);
    std::string line = std::string(head) + msg + "\n";
    if (!g_sink) {
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fflush(stdout);
    }
    if (g_sink) g_sink(line);
    if (g_log.is_open()) {
        g_log.write(line.data(), (std::streamsize)line.size());
        g_log.flush();
    }
}

bool is_admin() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e{};
    DWORD sz = 0;
    bool r = GetTokenInformation(tok, TokenElevation, &e, sizeof e, &sz) && e.TokenIsElevated;
    CloseHandle(tok);
    return r;
}

bool enable_privilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool r = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid) &&
             AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return r;
}

int run(const std::wstring& cmdline, std::string* output, DWORD timeout_ms) {
    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
    buf.push_back(L'\0');
    BOOL started = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!started) {
        CloseHandle(rd);
        return -1;
    }

    std::string out;
    char chunk[4096];
    DWORD got = 0;
    while (ReadFile(rd, chunk, sizeof chunk, &got, nullptr) && got) out.append(chunk, got);
    CloseHandle(rd);

    DWORD code = (DWORD)-1;
    if (WaitForSingleObject(pi.hProcess, timeout_ms) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    else TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (output) *output = out;
    return (int)code;
}

std::string read_secret(const std::string& prompt) {
    std::fputs(prompt.c_str(), stdout);
    std::fflush(stdout);
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    std::string result;
    if (GetConsoleMode(in, &mode)) {
        SetConsoleMode(in, mode & ~ENABLE_ECHO_INPUT);
        wchar_t buf[512];
        DWORD n = 0;
        ReadConsoleW(in, buf, 511, &n, nullptr);
        SetConsoleMode(in, mode);
        std::wstring w(buf, n);
        while (!w.empty() && (w.back() == L'\r' || w.back() == L'\n')) w.pop_back();
        result = narrow(w);
        std::fputs("\n", stdout);
    } else {
        std::getline(std::cin, result);
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n')) result.pop_back();
    }
    return result;
}

}  // namespace pm
