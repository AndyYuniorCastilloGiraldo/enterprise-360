package auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Propiedades de configuración JWT leídas desde {@code application.yml}.
 *
 * <ul>
 *   <li>{@code jwt.secret} → clave HMAC-SHA-512 codificada en Base64, inyectada
 *       desde la variable de entorno {@code JWT_SECRET}.
 *   <li>{@code jwt.expiration-ms} → tiempo de vida del token en milisegundos
 *       (por defecto 1 hora).
 * </ul>
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        long expirationMs,
        long refreshExpirationMs) {

    private static final long MAX_ACCESS_EXPIRATION_MS = 86_400_000L;
    private static final long MAX_REFRESH_EXPIRATION_MS = 7_776_000_000L;

    @ConstructorBinding
    public JwtProperties(
            String secret,
            long expirationMs,
            @DefaultValue("604800000") long refreshExpirationMs) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("JWT secret must be configured.");
        }
        if (expirationMs <= 0 || expirationMs > MAX_ACCESS_EXPIRATION_MS
                || refreshExpirationMs <= 0
                || refreshExpirationMs > MAX_REFRESH_EXPIRATION_MS) {
            throw new IllegalArgumentException("JWT expirations are outside the allowed limits.");
        }
        this.secret = secret;
        this.expirationMs = expirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    public JwtProperties(String secret, long expirationMs) {
        this(secret, expirationMs, 604_800_000L);
    }
}
