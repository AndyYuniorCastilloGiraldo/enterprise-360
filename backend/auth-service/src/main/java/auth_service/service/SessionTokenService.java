package auth_service.service;

import java.util.List;

import auth_service.entity.Empresa;
import auth_service.entity.Usuario;
import auth_service.security.AuthPrincipal;
import auth_service.security.SessionTokens;

public interface SessionTokenService {

    SessionTokens startSession(Usuario usuario, Empresa empresa, List<String> roles);

    SessionTokens rotate(String refreshToken);

    void revoke(AuthPrincipal principal);

    void revokeAllForUser(AuthPrincipal principal);

    boolean isActive(AuthPrincipal principal);
}
