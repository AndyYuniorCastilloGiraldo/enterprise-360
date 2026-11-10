package auth_service.service.impl;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import auth_service.dto.UsuarioCreateRequest;
import auth_service.entity.Empresa;
import auth_service.entity.Usuario;
import auth_service.repository.EmpresaRepository;
import auth_service.repository.RolRepository;
import auth_service.repository.UsuarioRepository;
import auth_service.repository.UsuarioRolRepository;

@ExtendWith(MockitoExtension.class)
class UsuarioServiceImplTest {

    private static final String RAW_PASSWORD = "Secure-passphrase-2026!";

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private EmpresaRepository empresaRepository;

    @Mock
    private RolRepository rolRepository;

    @Mock
    private UsuarioRolRepository usuarioRolRepository;

    private PasswordEncoder passwordEncoder;
    private UsuarioServiceImpl usuarioService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        usuarioService = new UsuarioServiceImpl(
                usuarioRepository,
                empresaRepository,
                rolRepository,
                usuarioRolRepository,
                passwordEncoder);
    }

    @Test
    void registrarCodificaLaContrasenaAntesDeGuardar() {
        UUID empresaId = UUID.randomUUID();
        Empresa empresa = Empresa.builder().id(empresaId).build();
        when(empresaRepository.findById(empresaId)).thenReturn(Optional.of(empresa));
        when(usuarioRepository.existsByEmailAndEmpresa_Id("ana@example.com", empresaId)).thenReturn(false);
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(invocation -> invocation.getArgument(0));

        usuarioService.registrar(new UsuarioCreateRequest(
                empresaId, "Ana", "Pérez", "ana@example.com", RAW_PASSWORD));

        ArgumentCaptor<Usuario> usuarioCaptor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(usuarioCaptor.capture());
        String storedPassword = usuarioCaptor.getValue().getPasswordHash();

        assertNotEquals(RAW_PASSWORD, storedPassword);
        assertTrue(passwordEncoder.matches(RAW_PASSWORD, storedPassword));
    }
}
