package auth_service.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import auth_service.dto.LoginRequest;
import auth_service.dto.LoginResponse;
import auth_service.dto.RefreshTokenRequest;
import auth_service.dto.ChangePasswordRequest;
import auth_service.entity.Empresa;
import auth_service.entity.Rol;
import auth_service.entity.Usuario;
import auth_service.entity.UsuarioRol;
import auth_service.exception.InvalidCredentialsException;
import auth_service.repository.EmpresaRepository;
import auth_service.repository.UsuarioRepository;
import auth_service.repository.UsuarioRolRepository;
import auth_service.security.SessionTokens;
import auth_service.security.AuthPrincipal;
import auth_service.service.SessionTokenService;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final String RUC = "20123456789";
    private static final String EMAIL = "ana@example.com";
    private static final String PASSWORD = "Secure-passphrase-2026!";
    private static final String PASSWORD_HASH = "$2a$test-hash";
    private static final String TOKEN = "signed.jwt.token";

    private final UUID empresaId = UUID.randomUUID();
    private final UUID usuarioId = UUID.randomUUID();

    @Mock
    private EmpresaRepository empresaRepository;

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private UsuarioRolRepository usuarioRolRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SessionTokenService sessionTokenService;

    private AuthServiceImpl authService;
    private Empresa empresa;
    private Usuario usuario;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(
                empresaRepository,
                usuarioRepository,
                usuarioRolRepository,
                passwordEncoder,
                sessionTokenService);
        empresa = Empresa.builder()
                .id(empresaId)
                .razonSocial("Empresa de prueba")
                .ruc(RUC)
                .activo(true)
                .createdAt(OffsetDateTime.now())
                .build();
        usuario = Usuario.builder()
                .id(usuarioId)
                .empresa(empresa)
                .nombres("Ana")
                .apellidos("Pérez")
                .email(EMAIL)
                .passwordHash(PASSWORD_HASH)
                .activo(true)
                .createdAt(OffsetDateTime.now())
                .build();
    }

    @Test
    void loginValidoEmiteTokenConTenantRolesYDatosBasicos() {
        Rol admin = Rol.builder()
                .id(UUID.randomUUID())
                .nombre("ADMIN")
                .descripcion("Administrador")
                .build();
        when(empresaRepository.findByRuc(RUC)).thenReturn(Optional.of(empresa));
        when(usuarioRepository.findByEmailAndEmpresa_Id(EMAIL, empresaId))
                .thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(true);
        when(usuarioRolRepository.findAllByUsuarioId(usuarioId))
                .thenReturn(List.of(UsuarioRol.builder().usuario(usuario).rol(admin).build()));
        when(sessionTokenService.startSession(usuario, empresa, List.of("ADMIN")))
                .thenReturn(new SessionTokens(
                        usuarioId, empresaId, UUID.randomUUID(), TOKEN, "refresh-token", 3600, 604800));

        LoginResponse response = authService.login(request());

        assertEquals(TOKEN, response.accessToken());
        assertEquals("refresh-token", response.refreshToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(3600, response.expiresInSeconds());
        assertEquals(604800, response.refreshExpiresInSeconds());
        assertEquals(usuarioId, response.usuario().id());
        assertEquals(empresaId, response.usuario().empresaId());
        assertEquals(EMAIL, response.usuario().email());
        assertEquals(empresaId, response.empresa().id());
        assertEquals(RUC, response.empresa().ruc());
        assertEquals(List.of("ADMIN"), response.roles().stream().map(role -> role.nombre()).toList());
        verify(sessionTokenService).startSession(usuario, empresa, List.of("ADMIN"));
    }

    @Test
    void loginRechazaRucDesconocido() {
        when(empresaRepository.findByRuc(RUC)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request()));
        verifyNoInteractions(usuarioRepository, passwordEncoder, sessionTokenService);
    }

    @Test
    void loginRechazaEmpresaInactiva() {
        empresa.setActivo(false);
        when(empresaRepository.findByRuc(RUC)).thenReturn(Optional.of(empresa));

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request()));
        verifyNoInteractions(usuarioRepository, passwordEncoder, sessionTokenService);
    }

    @Test
    void loginBuscaUsuarioEnLaEmpresaIndicada() {
        when(empresaRepository.findByRuc(RUC)).thenReturn(Optional.of(empresa));
        when(usuarioRepository.findByEmailAndEmpresa_Id(EMAIL, empresaId))
                .thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request()));
        verifyNoInteractions(passwordEncoder, sessionTokenService);
    }

    @Test
    void loginRechazaUsuarioInactivo() {
        usuario.setActivo(false);
        when(empresaRepository.findByRuc(RUC)).thenReturn(Optional.of(empresa));
        when(usuarioRepository.findByEmailAndEmpresa_Id(EMAIL, empresaId))
                .thenReturn(Optional.of(usuario));

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request()));
        verifyNoInteractions(passwordEncoder, sessionTokenService);
    }

    @Test
    void loginRechazaContrasenaIncorrecta() {
        when(empresaRepository.findByRuc(RUC)).thenReturn(Optional.of(empresa));
        when(usuarioRepository.findByEmailAndEmpresa_Id(EMAIL, empresaId))
                .thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(false);

        InvalidCredentialsException exception = assertThrows(
                InvalidCredentialsException.class, () -> authService.login(request()));
        assertEquals("Credenciales inválidas o cuenta inactiva.", exception.getMessage());
        verifyNoInteractions(sessionTokenService);
    }

    @Test
    void refreshRotaElTokenYDevuelveDatosDeSuTenant() {
        SessionTokens tokens = new SessionTokens(
                usuarioId, empresaId, UUID.randomUUID(), TOKEN, "next-refresh", 900, 604800);
        when(sessionTokenService.rotate("old-refresh")).thenReturn(tokens);
        when(usuarioRepository.findByIdAndEmpresa_Id(usuarioId, empresaId))
                .thenReturn(Optional.of(usuario));
        when(empresaRepository.findById(empresaId)).thenReturn(Optional.of(empresa));
        when(usuarioRolRepository.findAllByUsuarioId(usuarioId)).thenReturn(List.of());

        LoginResponse response = authService.refresh(new RefreshTokenRequest("old-refresh"));

        assertEquals(TOKEN, response.accessToken());
        assertEquals("next-refresh", response.refreshToken());
        assertEquals(empresaId, response.empresa().id());
        verify(sessionTokenService).rotate("old-refresh");
    }

    @Test
    void cambiarContrasenaCodificaLaNuevaYRevocaSesiones() {
        AuthPrincipal principal = principal();
        when(usuarioRepository.findByIdAndEmpresa_Id(usuarioId, empresaId))
                .thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("current-password", PASSWORD_HASH)).thenReturn(true);
        when(passwordEncoder.encode("Another-secure-passphrase-2026!")).thenReturn("$2a$new-hash");

        authService.changePassword(
                principal,
                new ChangePasswordRequest("current-password", "Another-secure-passphrase-2026!"));

        assertEquals("$2a$new-hash", usuario.getPasswordHash());
        verify(usuarioRepository).save(usuario);
        verify(sessionTokenService).revokeAllForUser(principal);
    }

    @Test
    void cambiarContrasenaRechazaLaContrasenaActualIncorrecta() {
        AuthPrincipal principal = principal();
        when(usuarioRepository.findByIdAndEmpresa_Id(usuarioId, empresaId))
                .thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("wrong-password", PASSWORD_HASH)).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.changePassword(
                principal,
                new ChangePasswordRequest("wrong-password", "Another-secure-passphrase-2026!")));

        verifyNoInteractions(sessionTokenService);
    }

    private AuthPrincipal principal() {
        return new AuthPrincipal(usuarioId, empresaId, UUID.randomUUID(), List.of("USER"));
    }

    private static LoginRequest request() {
        return new LoginRequest(RUC, EMAIL, PASSWORD);
    }
}
