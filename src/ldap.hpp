#pragma once
#include <string>
#include <vector>

namespace pm {

struct AdUser {
    std::string sam, display, mail, sid, upn;
    unsigned long uac = 0;
    bool enabled = true;
    std::string status;  // "Activa", "DESHABILITADA", ...
};

// Consultas LDAP con wldap32 (nativo). Bind Negotiate (Kerberos/NTLM) con firma y cifrado: no envia la
// contrasena en claro, no necesita certificados.
// `query` vacio = todos (hasta max_results). Coincide por usuario, nombre o correo.
std::vector<AdUser> ad_find_users(const std::string& dc, const std::string& domain, const std::string& admin,
                                  const std::string& password, const std::string& query, int max_results = 50);
std::vector<std::string> ad_list_ous(const std::string& dc, const std::string& domain, const std::string& admin,
                                     const std::string& password);

// Descubre un DC del dominio con DsGetDcName (usa el DNS actual). Devuelve "" si no hay.
std::string discover_dc(const std::string& domain);
// Dominio al que esta unido este equipo ("" si grupo de trabajo).
std::string current_domain();

}  // namespace pm
