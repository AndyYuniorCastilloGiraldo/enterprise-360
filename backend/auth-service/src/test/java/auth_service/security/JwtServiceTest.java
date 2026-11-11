package auth_service.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import auth_service.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Tests unitarios de {@link JwtService}.
 *
 * <p>No levanta el contexto de Spring; instancia el servicio directamente con
 * una {@link JwtProperties} construida en memoria para evitar depender de
 * variables de entorno.
 *
 * <p>La clave de prueba tiene 64 bytes (512 bits) codificados en Base64, lo que
 * satisface el mínimo requerido por HMAC-SHA-512.
 */
class JwtServiceTest {

    // 64 bytes en Base64 → clave válida para HS512
    private static final String SECRET_B64 =
            Base64.getEncoder().encodeToString(new byte[64]);

    private JwtService jwtService;

    private final UUID usuarioId = UUID.randomUUID();
    private final UUID empresaId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final List<String> roles = List.of("ADMIN", "USER");

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties(SECRET_B64, 3_600_000L);
        jwtService = new JwtService(props);
    }

    // -------------------------------------------------------------------------
    // generarToken
    // -------------------------------------------------------------------------

    @Test
    void generarToken_retornaStringNoNulo() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void generarToken_tieneFormatoJwtTresParts() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        // JWT compacto: header.payload.signature
        assertEquals(3, token.split("\\.").length,
                "El token debe tener exactamente tres partes separadas por '.'");
    }

    // -------------------------------------------------------------------------
    // esValido
    // -------------------------------------------------------------------------

    @Test
    void esValido_tokenRecienGenerado_esTrue() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        assertTrue(jwtService.esValido(token));
    }

    @Test
    void esValido_tokenMalformado_esFalse() {
        assertFalse(jwtService.esValido("esto.no.es.un.jwt.valido"));
    }

    @Test
    void esValido_tokenConFirmaAlterada_esFalse() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        int inicioFirma = token.lastIndexOf('.') + 1;
        char primerCaracterFirma = token.charAt(inicioFirma);
        char caracterAlterado = primerCaracterFirma == 'A' ? 'B' : 'A';
        String corrupto = token.substring(0, inicioFirma)
                + caracterAlterado
                + token.substring(inicioFirma + 1);
        assertFalse(jwtService.esValido(corrupto));
    }

    @Test
    void esValido_tokenExpirado_esFalse() throws InterruptedException {
        // Token con expiración de 1 ms → ya expiró al validar
        JwtProperties propsCortas = new JwtProperties(SECRET_B64, 1L);
        JwtService servicioCorto = new JwtService(propsCortas);
        String token = servicioCorto.generarToken(usuarioId, empresaId, sessionId, roles);
        Thread.sleep(10);
        assertFalse(servicioCorto.esValido(token));
    }

    // -------------------------------------------------------------------------
    // extraerUsuarioId
    // -------------------------------------------------------------------------

    @Test
    void extraerUsuarioId_coincideConElUsadoAlGenerar() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        assertEquals(usuarioId, jwtService.extraerUsuarioId(token));
    }

    // -------------------------------------------------------------------------
    // extraerEmpresaId
    // -------------------------------------------------------------------------

    @Test
    void extraerEmpresaId_coincideConElUsadoAlGenerar() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        assertEquals(empresaId, jwtService.extraerEmpresaId(token));
    }

    // -------------------------------------------------------------------------
    // extraerRoles
    // -------------------------------------------------------------------------

    @Test
    void extraerRoles_coincideConLosUsadosAlGenerar() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        assertEquals(roles, jwtService.extraerRoles(token));
    }

    @Test
    void parsearPrincipalExponeIdentidadTenantSesionYRolesValidados() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);

        AuthPrincipal principal = jwtService.parsearPrincipal(token);

        assertEquals(usuarioId, principal.usuarioId());
        assertEquals(empresaId, principal.empresaId());
        assertEquals(sessionId, principal.sessionId());
        assertEquals(roles, principal.roles());
        assertEquals("ROLE_ADMIN", principal.authorities().iterator().next().getAuthority());
        assertTrue(principal.permissions().isEmpty());
    }

    @Test
    void esValido_rechazaIssuerTenantYUsoDeTokenIncorrectos() {
        assertFalse(jwtService.esValido(signedToken(
                "otro-issuer", empresaId.toString(), "access")));
        assertFalse(jwtService.esValido(signedToken(
                "enterprise-360-auth-service", "not-a-uuid", "access")));
        assertFalse(jwtService.esValido(signedToken(
                "enterprise-360-auth-service", empresaId.toString(), "refresh")));
    }

    @Test
    void autoridadesIncluyenPermisosGranulares() {
        String token = jwtService.generarToken(
                usuarioId, empresaId, sessionId, roles, List.of("USERS_READ"));

        assertTrue(jwtService.parsearPrincipal(token).authorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("PERM_USERS_READ")));
    }

    @Test
    void tokenNoContienePasswordNiHash() {
        String token = jwtService.generarToken(usuarioId, empresaId, sessionId, roles);
        // El payload es la parte central del JWT (índice 1), decodificado en Base64
        String payloadB64 = token.split("\\.")[1];
        // Base64 URL-safe sin padding → añadimos padding si hace falta
        int pad = payloadB64.length() % 4;
        if (pad != 0) payloadB64 += "=".repeat(4 - pad);
        String payload = new String(Base64.getUrlDecoder().decode(payloadB64));

        assertFalse(payload.contains("password"),
                "El JWT no debe contener ningún campo 'password'");
        assertFalse(payload.contains("hash"),
                "El JWT no debe contener ningún campo 'hash'");
    }

    private String signedToken(String issuer, String tenantId, String tokenUse) {
        Date issuedAt = new Date();
        SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(SECRET_B64));
        return Jwts.builder()
                .issuer(issuer)
                .audience().add("enterprise-360-api").and()
                .subject(usuarioId.toString())
                .claim(JwtService.CLAIM_EMPRESA_ID, tenantId)
                .claim(JwtService.CLAIM_SESSION_ID, sessionId.toString())
                .claim(JwtService.CLAIM_ROLES, roles)
                .claim(JwtService.CLAIM_PERMISSIONS, List.of())
                .claim(JwtService.CLAIM_TOKEN_USE, tokenUse)
                .issuedAt(issuedAt)
                .expiration(new Date(issuedAt.getTime() + 60_000L))
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }
}
