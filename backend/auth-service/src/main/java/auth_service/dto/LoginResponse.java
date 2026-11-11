package auth_service.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Tokens de la sesión y perfil básico autenticado.")
public record LoginResponse(
        @Schema(description = "JWT de acceso; enviar como Bearer token")
        String accessToken,
        @Schema(description = "Refresh token opaco. Se almacena su hash en el servidor.")
        String refreshToken,
        String tokenType,
        long expiresInSeconds,
        long refreshExpiresInSeconds,
        UsuarioResponse usuario,
        EmpresaResponse empresa,
        List<RolResponse> roles) {
}
