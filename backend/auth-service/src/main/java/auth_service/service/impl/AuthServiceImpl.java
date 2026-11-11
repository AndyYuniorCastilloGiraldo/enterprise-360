package auth_service.service.impl;

import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth_service.dto.ChangePasswordRequest;
import auth_service.dto.EmpresaResponse;
import auth_service.dto.LoginRequest;
import auth_service.dto.LoginResponse;
import auth_service.dto.RefreshTokenRequest;
import auth_service.dto.RolResponse;
import auth_service.dto.SessionInfoResponse;
import auth_service.dto.UsuarioResponse;
import auth_service.entity.Empresa;
import auth_service.entity.Usuario;
import auth_service.exception.InvalidCredentialsException;
import auth_service.exception.InvalidRefreshTokenException;
import auth_service.repository.EmpresaRepository;
import auth_service.repository.UsuarioRepository;
import auth_service.repository.UsuarioRolRepository;
import auth_service.security.AuthPrincipal;
import auth_service.security.SessionTokens;
import auth_service.service.AuthService;
import auth_service.service.SessionTokenService;

@Service
public class AuthServiceImpl implements AuthService {

    private static final String BEARER_TOKEN_TYPE = "Bearer";

    private final EmpresaRepository empresaRepository;
    private final UsuarioRepository usuarioRepository;
    private final UsuarioRolRepository usuarioRolRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionTokenService sessionTokenService;

    public AuthServiceImpl(
            EmpresaRepository empresaRepository,
            UsuarioRepository usuarioRepository,
            UsuarioRolRepository usuarioRolRepository,
            PasswordEncoder passwordEncoder,
            SessionTokenService sessionTokenService) {
        this.empresaRepository = empresaRepository;
        this.usuarioRepository = usuarioRepository;
        this.usuarioRolRepository = usuarioRolRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionTokenService = sessionTokenService;
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        Empresa empresa = empresaRepository.findByRuc(request.ruc())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidCredentialsException::new);

        Usuario usuario = usuarioRepository
                .findByEmailAndEmpresa_Id(request.email(), empresa.getId())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(request.password(), usuario.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        List<RolResponse> roles = findRoles(usuario.getId());
        List<String> roleNames = roles.stream().map(RolResponse::nombre).toList();
        SessionTokens tokens = sessionTokenService.startSession(usuario, empresa, roleNames);
        return toLoginResponse(tokens, usuario, empresa, roles);
    }

    @Override
    public LoginResponse refresh(RefreshTokenRequest request) {
        SessionTokens tokens = sessionTokenService.rotate(request.refreshToken());
        Usuario usuario = usuarioRepository
                .findByIdAndEmpresa_Id(tokens.usuarioId(), tokens.empresaId())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidRefreshTokenException::new);
        Empresa empresa = empresaRepository.findById(tokens.empresaId())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidRefreshTokenException::new);
        return toLoginResponse(tokens, usuario, empresa, findRoles(usuario.getId()));
    }

    @Override
    @Transactional(readOnly = true)
    public SessionInfoResponse me(AuthPrincipal principal) {
        Usuario usuario = usuarioRepository
                .findByIdAndEmpresa_Id(principal.usuarioId(), principal.empresaId())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidCredentialsException::new);
        Empresa empresa = empresaRepository.findById(principal.empresaId())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidCredentialsException::new);
        return new SessionInfoResponse(
                toUsuarioResponse(usuario),
                toEmpresaResponse(empresa),
                findRoles(usuario.getId()));
    }

    @Override
    public void logout(AuthPrincipal principal) {
        sessionTokenService.revoke(principal);
    }

    @Override
    @Transactional
    public void changePassword(AuthPrincipal principal, ChangePasswordRequest request) {
        Usuario usuario = usuarioRepository
                .findByIdAndEmpresa_Id(principal.usuarioId(), principal.empresaId())
                .filter(found -> Boolean.TRUE.equals(found.getActivo()))
                .orElseThrow(InvalidCredentialsException::new);
        if (!Boolean.TRUE.equals(usuario.getEmpresa().getActivo())
                || !passwordEncoder.matches(request.currentPassword(), usuario.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        usuario.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        usuarioRepository.save(usuario);
        sessionTokenService.revokeAllForUser(principal);
    }

    private List<RolResponse> findRoles(java.util.UUID usuarioId) {
        return usuarioRolRepository.findAllByUsuarioId(usuarioId).stream()
                .map(usuarioRol -> {
                    var rol = usuarioRol.getRol();
                    return new RolResponse(rol.getId(), rol.getNombre(), rol.getDescripcion());
                })
                .toList();
    }

    private static LoginResponse toLoginResponse(
            SessionTokens tokens,
            Usuario usuario,
            Empresa empresa,
            List<RolResponse> roles) {
        return new LoginResponse(
                tokens.accessToken(),
                tokens.refreshToken(),
                BEARER_TOKEN_TYPE,
                tokens.accessExpiresInSeconds(),
                tokens.refreshExpiresInSeconds(),
                toUsuarioResponse(usuario),
                toEmpresaResponse(empresa),
                roles);
    }

    private static UsuarioResponse toUsuarioResponse(Usuario usuario) {
        return new UsuarioResponse(
                usuario.getId(),
                usuario.getEmpresa().getId(),
                usuario.getNombres(),
                usuario.getApellidos(),
                usuario.getEmail(),
                usuario.getActivo(),
                usuario.getCreatedAt());
    }

    private static EmpresaResponse toEmpresaResponse(Empresa empresa) {
        return new EmpresaResponse(
                empresa.getId(),
                empresa.getRazonSocial(),
                empresa.getRuc(),
                empresa.getActivo(),
                empresa.getCreatedAt());
    }
}
