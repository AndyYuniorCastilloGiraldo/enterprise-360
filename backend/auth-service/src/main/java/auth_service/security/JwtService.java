package auth_service.security;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import auth_service.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
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
    static final String CLAIM_SESSION_ID = "sid";
    static final String CLAIM_TOKEN_USE = "token_use";
    static final String CLAIM_PERMISSIONS = "permissions";
    private static final String ACCESS_TOKEN_USE = "access";
    private static final String ISSUER = "enterprise-360-auth-service";
    private static final String AUDIENCE = "enterprise-360-api";

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
    /**
     * Genera un token de acceso ligado a una sesión persistente.
     */
    public String generarToken(UUID usuarioId, UUID empresaId, UUID sessionId, List<String> roles) {
        return generarToken(usuarioId, empresaId, sessionId, roles, List.of());
    }

    public String generarToken(
            UUID usuarioId,
            UUID empresaId,
            UUID sessionId,
            List<String> roles,
            List<String> permissions) {
        Date ahora = new Date();
        Date expiracion = new Date(ahora.getTime() + expirationMs);

        return Jwts.builder()
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .subject(usuarioId.toString())
                .claim(CLAIM_EMPRESA_ID, empresaId.toString())
                .claim(CLAIM_SESSION_ID, sessionId.toString())
                .claim(CLAIM_ROLES, roles)
                .claim(CLAIM_PERMISSIONS, permissions)
                .claim(CLAIM_TOKEN_USE, ACCESS_TOKEN_USE)
                .issuedAt(ahora)
                .expiration(expiracion)
                .signWith(signingKey, Jwts.SIG.HS512)
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
            parsearPrincipal(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public AuthPrincipal parsearPrincipal(String token) {
        Jws<Claims> signedJwt = Jwts.parser()
                .requireIssuer(ISSUER)
                .requireAudience(AUDIENCE)
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token);
        if (!Jwts.SIG.HS512.getId().equals(signedJwt.getHeader().getAlgorithm())) {
            throw new JwtException("Unsupported JWT signing algorithm.");
        }

        Claims claims = signedJwt.getPayload();
        if (!ACCESS_TOKEN_USE.equals(claims.get(CLAIM_TOKEN_USE, String.class))) {
            throw new JwtException("JWT is not an access token.");
        }
        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();
        if (issuedAt == null || expiration == null
                || expiration.getTime() <= issuedAt.getTime()
                || expiration.getTime() - issuedAt.getTime() > expirationMs + 1_000L
                || issuedAt.after(new Date(System.currentTimeMillis() + 30_000L))) {
            throw new JwtException("Invalid JWT timestamps.");
        }

        Object rawRoles = claims.get(CLAIM_ROLES);
        List<String> roleClaims = readNamesClaim(rawRoles, "roles");
        List<String> permissionClaims = readNamesClaim(claims.get(CLAIM_PERMISSIONS), "permissions");

        try {
            return new AuthPrincipal(
                    UUID.fromString(claims.getSubject()),
                    UUID.fromString(claims.get(CLAIM_EMPRESA_ID, String.class)),
                    UUID.fromString(claims.get(CLAIM_SESSION_ID, String.class)),
                    roleClaims,
                    permissionClaims);
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new JwtException("Invalid JWT identity claims.", exception);
        }
    }

    /**
     * Extrae el ID del usuario (claim {@code sub}) del token.
     *
     * @param token token JWT válido.
     * @return UUID del usuario.
     */
    public UUID extraerUsuarioId(String token) {
        return parsearPrincipal(token).usuarioId();
    }

    /**
     * Extrae el ID de la empresa del token.
     *
     * @param token token JWT válido.
     * @return UUID de la empresa.
     */
    public UUID extraerEmpresaId(String token) {
        return parsearPrincipal(token).empresaId();
    }

    public UUID extraerSessionId(String token) {
        return parsearPrincipal(token).sessionId();
    }

    /**
     * Extrae la lista de roles del token.
     *
     * @param token token JWT válido.
     * @return lista de nombres de roles.
     */
    @SuppressWarnings("unchecked")
    public List<String> extraerRoles(String token) {
        return parsearPrincipal(token).roles();
    }

    private static List<String> readNamesClaim(Object value, String claimName) {
        if (!(value instanceof List<?> names)
                || names.stream().anyMatch(name -> !(name instanceof String text) || text.isBlank())) {
            throw new JwtException("Invalid JWT " + claimName + ".");
        }
        return names.stream().map(String.class::cast).toList();
    }
}
