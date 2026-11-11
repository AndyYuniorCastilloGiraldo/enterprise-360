package auth_service.security;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import auth_service.entity.Empresa;
import auth_service.entity.Rol;
import auth_service.entity.Usuario;
import auth_service.entity.UsuarioRol;
import auth_service.entity.UsuarioRolId;
import auth_service.repository.EmpresaRepository;
import auth_service.repository.RefreshTokenRepository;
import auth_service.repository.RolRepository;
import auth_service.repository.UsuarioRepository;
import auth_service.repository.UsuarioRolRepository;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthSessionIntegrationTest {

    private static final AtomicLong RUC_SEQUENCE = new AtomicLong(20_000_000_000L);
    private static final String PASSWORD = "Secure-passphrase-2026!";

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private EmpresaRepository empresaRepository;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private RolRepository rolRepository;

    @Autowired
    private UsuarioRolRepository usuarioRolRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Empresa empresa;
    private Usuario usuario;
    private Usuario usuarioRegular;

    @BeforeEach
    void setUp() {
        empresa = empresaRepository.saveAndFlush(Empresa.builder()
                .razonSocial("Empresa de integración " + UUID.randomUUID())
                .ruc(String.format("%011d", RUC_SEQUENCE.incrementAndGet()))
                .activo(true)
                .build());
        usuario = usuarioRepository.saveAndFlush(Usuario.builder()
                .empresa(empresa)
                .nombres("Ana")
                .apellidos("Prueba")
                .email("ana-" + UUID.randomUUID() + "@example.com")
                .passwordHash(passwordEncoder.encode(PASSWORD))
                .activo(true)
                .build());
        usuarioRegular = usuarioRepository.saveAndFlush(Usuario.builder()
                .empresa(empresa)
                .nombres("Luis")
                .apellidos("Prueba")
                .email("luis-" + UUID.randomUUID() + "@example.com")
                .passwordHash(passwordEncoder.encode(PASSWORD))
                .activo(true)
                .build());
        asignarRol(usuario, role("ADMIN"));
        asignarRol(usuarioRegular, role("USER"));
    }

    @Test
    void loginMeRotacionYReutilizacionRevocanTodaLaSesion() throws Exception {
        JsonNode login = login(empresa.getRuc(), PASSWORD, 200);
        String accessToken = login.path("accessToken").asText();
        String firstRefreshToken = login.path("refreshToken").asText();
        org.junit.jupiter.api.Assertions.assertTrue(
                refreshTokenRepository.findAll().stream()
                        .noneMatch(token -> token.getTokenHash().equals(firstRefreshToken)));

        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuario.id").value(usuario.getId().toString()))
                .andExpect(jsonPath("$.usuario.empresaId").value(empresa.getId().toString()))
                .andExpect(jsonPath("$.empresa.id").value(empresa.getId().toString()))
                .andExpect(jsonPath("$.roles[0].nombre").value("ADMIN"));

        JsonNode rotated = postJson("/api/auth/refresh",
                "{\"refreshToken\":\"" + firstRefreshToken + "\"}", 200);
        String rotatedAccessToken = rotated.path("accessToken").asText();
        String rotatedRefreshToken = rotated.path("refreshToken").asText();
        assertNotEquals(firstRefreshToken, rotatedRefreshToken);

        postJson("/api/auth/refresh",
                "{\"refreshToken\":\"" + firstRefreshToken + "\"}", 401);
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", bearer(rotatedAccessToken)))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh",
                "{\"refreshToken\":\"" + rotatedRefreshToken + "\"}", 401);
    }

    @Test
    void noPermiteAutenticarUsuarioUsandoRucDeOtraEmpresa() throws Exception {
        Empresa otraEmpresa = empresaRepository.saveAndFlush(Empresa.builder()
                .razonSocial("Otra empresa " + UUID.randomUUID())
                .ruc(String.format("%011d", RUC_SEQUENCE.incrementAndGet()))
                .activo(true)
                .build());

        login(otraEmpresa.getRuc(), PASSWORD, 401);
    }

    @Test
    void autorizacionPorRolesPermiteAdminYRechazaUsuarioSinEseRol() throws Exception {
        JsonNode adminLogin = login(empresa.getRuc(), usuario.getEmail(), PASSWORD, 200);
        JsonNode userLogin = login(empresa.getRuc(), usuarioRegular.getEmail(), PASSWORD, 200);

        mockMvc.perform(get("/__test/admin")
                        .header("Authorization", bearer(adminLogin.path("accessToken").asText())))
                .andExpect(status().isOk());
        mockMvc.perform(get("/__test/admin")
                        .header("Authorization", bearer(userLogin.path("accessToken").asText())))
                .andExpect(status().isForbidden());
    }

    @Test
    void logoutRevocaRefreshTokenYJwtDeLaSesion() throws Exception {
        JsonNode login = login(empresa.getRuc(), PASSWORD, 200);
        String accessToken = login.path("accessToken").asText();
        String refreshToken = login.path("refreshToken").asText();

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", bearer(accessToken)))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(accessToken)))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh", "{\"refreshToken\":\"" + refreshToken + "\"}", 401);
    }

    @Test
    void cambioDeContrasenaRevocaSesionesYGuardaSoloBCrypt() throws Exception {
        JsonNode login = login(empresa.getRuc(), PASSWORD, 200);
        String accessToken = login.path("accessToken").asText();
        String newPassword = "Another-secure-passphrase-2026!";

        mockMvc.perform(post("/api/auth/change-password")
                        .header("Authorization", bearer(accessToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "Secure-passphrase-2026!",
                                  "newPassword": "Another-secure-passphrase-2026!"
                                }
                                """))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(accessToken)))
                .andExpect(status().isUnauthorized());
        login(empresa.getRuc(), PASSWORD, 401);
        login(empresa.getRuc(), newPassword, 200);

        Usuario changed = usuarioRepository.findById(usuario.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertTrue(
                passwordEncoder.matches(newPassword, changed.getPasswordHash()));
        org.junit.jupiter.api.Assertions.assertNotEquals(newPassword, changed.getPasswordHash());
    }

    @Test
    void rechazaJwtMalformadoYNoExponeAutenticacion() throws Exception {
        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer("not.a.jwt")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void openApiPublicaLosEndpointsDeAutenticacion() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/auth/login'].post").exists())
                .andExpect(jsonPath("$.paths['/api/auth/refresh'].post").exists())
                .andExpect(jsonPath("$.paths['/api/auth/me'].get").exists())
                .andExpect(jsonPath("$.paths['/api/auth/logout'].post").exists())
                .andExpect(jsonPath("$.paths['/api/auth/change-password'].post").exists());
    }

    private JsonNode login(String ruc, String password, int expectedStatus) throws Exception {
        return login(ruc, usuario.getEmail(), password, expectedStatus);
    }

    private JsonNode login(String ruc, String email, String password, int expectedStatus) throws Exception {
        return postJson("/api/auth/login", """
                {
                  "ruc": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(ruc, email, password), expectedStatus);
    }

    private JsonNode postJson(String path, String content, int expectedStatus) throws Exception {
        MvcResult result = mockMvc.perform(post(path)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content))
                .andExpect(status().is(expectedStatus))
                .andReturn();
        String responseBody = result.getResponse().getContentAsString();
        return responseBody.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(responseBody);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private Rol role(String name) {
        return rolRepository.findByNombre(name).orElseGet(() ->
                rolRepository.saveAndFlush(Rol.builder()
                        .nombre(name)
                        .descripcion(name + " de integración")
                        .build()));
    }

    private void asignarRol(Usuario targetUser, Rol role) {
        usuarioRolRepository.saveAndFlush(UsuarioRol.builder()
                .id(new UsuarioRolId(targetUser.getId(), role.getId()))
                .usuario(targetUser)
                .rol(role)
                .build());
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class RoleAuthorizationTestConfiguration {

        @Bean
        RoleAuthorizationTestController roleAuthorizationTestController() {
            return new RoleAuthorizationTestController();
        }
    }

    @RestController
    static class RoleAuthorizationTestController {

        @GetMapping("/__test/admin")
        @PreAuthorize("hasRole('ADMIN')")
        String adminOnly() {
            return "allowed";
        }
    }
}
