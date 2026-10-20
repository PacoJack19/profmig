#include "ldap.hpp"

#include "util.hpp"
// clang-format off
#include <lm.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <sspi.h>
// clang-format on

#include <algorithm>

#include "sid.hpp"

namespace pm {

namespace {

struct Conn {
    LDAP* ld = nullptr;
    Conn() = default;
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
    ~Conn() {
        if (ld) ldap_unbind(ld);
    }
};

std::wstring base_dn(const std::string& domain) {
    std::wstring dn, w = widen(domain);
    size_t start = 0;
    while (start <= w.size()) {
        size_t dot = w.find(L'.', start);
        std::wstring part = w.substr(start, dot == std::wstring::npos ? std::wstring::npos : dot - start);
        if (!part.empty()) dn += (dn.empty() ? L"DC=" : L",DC=") + part;
        if (dot == std::wstring::npos) break;
        start = dot + 1;
    }
    return dn;
}

void connect(Conn& c, const std::string& dc, const std::string& domain, const std::string& admin,
             const std::string& password) {
    std::wstring host = widen(dc);
    c.ld = ldap_initW(const_cast<PWSTR>(host.c_str()), 389);
    if (!c.ld) throw Fail("No se pudo inicializar LDAP hacia " + dc);
    ULONG v3 = LDAP_VERSION3;
    ldap_set_optionW(c.ld, LDAP_OPT_PROTOCOL_VERSION, &v3);
    ULONG timeout = 8;
    ldap_set_optionW(c.ld, LDAP_OPT_TIMELIMIT, &timeout);

    std::wstring user, dom, pass = widen(password);
    std::wstring a = widen(admin);
    size_t bs = a.find(L'\\');
    if (bs != std::wstring::npos) {
        dom = a.substr(0, bs);
        user = a.substr(bs + 1);
    } else if (a.find(L'@') != std::wstring::npos) {
        user = a;
    } else {
        user = a;
        dom = widen(domain);
    }

    SEC_WINNT_AUTH_IDENTITY_W id{};
    id.User = (unsigned short*)user.data();
    id.UserLength = (unsigned long)user.size();
    id.Domain = (unsigned short*)dom.data();
    id.DomainLength = (unsigned long)dom.size();
    id.Password = (unsigned short*)pass.data();
    id.PasswordLength = (unsigned long)pass.size();
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    ULONG rc = ldap_bind_sW(c.ld, nullptr, (PWSTR)&id, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        std::wstring msg = ldap_err2stringW(rc);
        throw Fail("No se pudo autenticar en LDAP (" + dc + "): " + narrow(msg));
    }
}

std::wstring escape_filter(const std::wstring& s) {
    std::wstring r;
    for (wchar_t ch : s) {
        switch (ch) {
            case L'*': r += L"\\2a"; break;
            case L'(': r += L"\\28"; break;
            case L')': r += L"\\29"; break;
            case L'\\': r += L"\\5c"; break;
            default: r += ch;
        }
    }
    return r;
}

std::string first_value(LDAP* ld, LDAPMessage* e, const wchar_t* attr) {
    PWSTR* v = ldap_get_valuesW(ld, e, const_cast<PWSTR>(attr));
    std::string r;
    if (v) {
        if (v[0]) r = narrow(v[0]);
        ldap_value_freeW(v);
    }
    return r;
}

}  // namespace

std::vector<AdUser> ad_find_users(const std::string& dc, const std::string& domain, const std::string& admin,
                                  const std::string& password, const std::string& query, int max_results) {
    Conn c;
    connect(c, dc, domain, admin, password);

    std::wstring q = escape_filter(widen(query));
    std::wstring filter = L"(&(objectCategory=person)(objectClass=user)";
    if (!q.empty())
        filter += L"(|(sAMAccountName=*" + q + L"*)(displayName=*" + q + L"*)(mail=*" + q + L"*)(sn=*" + q + L"*))";
    filter += L")";

    PWCHAR attrs[] = {const_cast<PWCHAR>(L"sAMAccountName"), const_cast<PWCHAR>(L"displayName"),
                      const_cast<PWCHAR>(L"mail"),           const_cast<PWCHAR>(L"userPrincipalName"),
                      const_cast<PWCHAR>(L"userAccountControl"), const_cast<PWCHAR>(L"objectSid"), nullptr};
    LDAP_TIMEVAL tv{15, 0};
    LDAPMessage* res = nullptr;
    std::wstring base = base_dn(domain);
    ULONG rc = ldap_search_ext_sW(c.ld, const_cast<PWSTR>(base.c_str()), LDAP_SCOPE_SUBTREE,
                                  const_cast<PWSTR>(filter.c_str()), attrs, 0, nullptr, nullptr, &tv, max_results, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        if (res) ldap_msgfree(res);
        throw Fail("Busqueda LDAP fallida: " + narrow(ldap_err2stringW(rc)));
    }

    std::vector<AdUser> out;
    for (LDAPMessage* e = ldap_first_entry(c.ld, res); e; e = ldap_next_entry(c.ld, e)) {
        AdUser u;
        u.sam = first_value(c.ld, e, L"sAMAccountName");
        if (u.sam.empty() || u.sam.back() == '$') continue;  // cuentas de equipo
        u.display = first_value(c.ld, e, L"displayName");
        u.mail = first_value(c.ld, e, L"mail");
        u.upn = first_value(c.ld, e, L"userPrincipalName");
        std::string uac = first_value(c.ld, e, L"userAccountControl");
        u.uac = uac.empty() ? 512 : std::strtoul(uac.c_str(), nullptr, 10);
        u.enabled = !(u.uac & 0x2);
        u.status = u.enabled ? "Activa" : "DESHABILITADA";
        if (u.uac & 0x10) u.status += ", bloqueada";
        PLDAP_BERVAL* sv = ldap_get_values_lenW(c.ld, e, const_cast<PWSTR>(L"objectSid"));
        if (sv) {
            if (sv[0]) u.sid = sid_to_string((PSID)sv[0]->bv_val);
            ldap_value_free_len(sv);
        }
        out.push_back(std::move(u));
    }
    ldap_msgfree(res);
    std::sort(out.begin(), out.end(), [](const AdUser& a, const AdUser& b) { return a.sam < b.sam; });
    return out;
}

std::vector<std::string> ad_list_ous(const std::string& dc, const std::string& domain, const std::string& admin,
                                     const std::string& password) {
    Conn c;
    connect(c, dc, domain, admin, password);
    PWCHAR attrs[] = {const_cast<PWCHAR>(L"distinguishedName"), nullptr};
    LDAP_TIMEVAL tv{15, 0};
    LDAPMessage* res = nullptr;
    std::wstring base = base_dn(domain);
    ULONG rc = ldap_search_ext_sW(c.ld, const_cast<PWSTR>(base.c_str()), LDAP_SCOPE_SUBTREE,
                                  const_cast<PWSTR>(L"(objectClass=organizationalUnit)"), attrs, 0, nullptr, nullptr,
                                  &tv, 1000, &res);
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        if (res) ldap_msgfree(res);
        throw Fail("Busqueda de OUs fallida: " + narrow(ldap_err2stringW(rc)));
    }
    std::vector<std::string> out;
    for (LDAPMessage* e = ldap_first_entry(c.ld, res); e; e = ldap_next_entry(c.ld, e))
        out.push_back(first_value(c.ld, e, L"distinguishedName"));
    ldap_msgfree(res);
    std::sort(out.begin(), out.end());
    return out;
}

std::string discover_dc(const std::string& domain) {
    PDOMAIN_CONTROLLER_INFOW info = nullptr;
    std::wstring d = widen(domain);
    DWORD rc = DsGetDcNameW(nullptr, d.c_str(), nullptr, nullptr, DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_PREFERRED,
                            &info);
    if (rc != ERROR_SUCCESS || !info) return "";
    std::wstring name = info->DomainControllerName;
    NetApiBufferFree(info);
    while (!name.empty() && name.front() == L'\\') name.erase(name.begin());
    return narrow(name);
}

std::string current_domain() {
    LPWSTR name = nullptr;
    NETSETUP_JOIN_STATUS st;
    std::string r;
    if (NetGetJoinInformation(nullptr, &name, &st) == NERR_Success) {
        if (st == NetSetupDomainName && name) r = narrow(name);
        NetApiBufferFree(name);
    }
    return r;
}

}  // namespace pm
