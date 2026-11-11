package auth_service.service;

import auth_service.dto.LoginRequest;
import auth_service.dto.LoginResponse;
import auth_service.dto.ChangePasswordRequest;
import auth_service.dto.RefreshTokenRequest;
import auth_service.dto.SessionInfoResponse;
import auth_service.security.AuthPrincipal;

public interface AuthService {

    LoginResponse login(LoginRequest request);

    LoginResponse refresh(RefreshTokenRequest request);

    SessionInfoResponse me(AuthPrincipal principal);

    void logout(AuthPrincipal principal);

    void changePassword(AuthPrincipal principal, ChangePasswordRequest request);
}
