package auth_service.security;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import auth_service.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Servicio responsable de generar, validar y extraer información de tokens JWT.
 *
 * <p>Utiliza HMAC-SHA-512 con una clave secreta de 512 bits (64 bytes mínimo)
 * configurada externamente en {@code jwt.secret}.
 *
 * <p>Claims incluidos en el token:
 * <ul>
 *   <li>{@code sub}       → ID del usuario (UUID como String).
 *   <li>{@code empresaId} → ID de la empresa a la que pertenece el usuario.
 *   <li>{@code roles}     → lista de nombres de roles del usuario.
 * </ul>
 *
 * <p>No se incluye ningún hash de contraseña ni dato sensible dentro del token.
 */
@Service
public class JwtService {

    static final String CLAIM_EMPRESA_ID = "empresaId";
    static final String CLAIM_ROLES = "roles";

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtService(JwtProperties jwtProperties) {
        this.signingKey = Keys.hmacShaKeyFor(
                java.util.Base64.getDecoder().decode(jwtProperties.secret()));
        this.expirationMs = jwtProperties.expirationMs();
    }

    /**
     * Genera un token JWT firmado.
     *
     * @param usuarioId ID del usuario (subject del token).
     * @param empresaId ID de la empresa a la que pertenece el usuario.
     * @param roles     lista de nombres de roles asignados al usuario.
     * @return token JWT compacto (header.payload.signature).
     */
    public String generarToken(UUID usuarioId, UUID empresaId, List<String> roles) {
        Date ahora = new Date();
        Date expiracion = new Date(ahora.getTime() + expirationMs);

        return Jwts.builder()
                .subject(usuarioId.toString())
                .claim(CLAIM_EMPRESA_ID, empresaId.toString())
                .claim(CLAIM_ROLES, roles)
                .issuedAt(ahora)
                .expiration(expiracion)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Valida un token JWT verificando su firma y que no haya expirado.
     *
     * @param token token JWT compacto.
     * @return {@code true} si el token es válido; {@code false} en caso contrario.
     */
    public boolean esValido(String token) {
        try {
            parsearClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Extrae el ID del usuario (claim {@code sub}) del token.
     *
     * @param token token JWT válido.
     * @return UUID del usuario.
     */
    public UUID extraerUsuarioId(String token) {
        return UUID.fromString(parsearClaims(token).getSubject());
    }

    /**
     * Extrae el ID de la empresa del token.
     *
     * @param token token JWT válido.
     * @return UUID de la empresa.
     */
    public UUID extraerEmpresaId(String token) {
        return UUID.fromString(parsearClaims(token).get(CLAIM_EMPRESA_ID, String.class));
    }

    /**
     * Extrae la lista de roles del token.
     *
     * @param token token JWT válido.
     * @return lista de nombres de roles.
     */
    @SuppressWarnings("unchecked")
    public List<String> extraerRoles(String token) {
        return parsearClaims(token).get(CLAIM_ROLES, List.class);
    }

    // -------------------------------------------------------------------------
    // helpers privados
    // -------------------------------------------------------------------------

    private Claims parsearClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}

