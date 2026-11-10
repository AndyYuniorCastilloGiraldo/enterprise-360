package auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

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
public record JwtProperties(String secret, long expirationMs) {
}

