package auth_service.security;

import java.util.UUID;

public record SessionTokens(
        UUID usuarioId,
        UUID empresaId,
        UUID sessionId,
        String accessToken,
        String refreshToken,
        long accessExpiresInSeconds,
        long refreshExpiresInSeconds) {
}
