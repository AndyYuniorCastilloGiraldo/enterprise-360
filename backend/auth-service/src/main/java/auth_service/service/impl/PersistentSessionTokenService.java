package auth_service.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth_service.config.JwtProperties;
import auth_service.entity.AuthSession;
import auth_service.entity.Empresa;
import auth_service.entity.RefreshToken;
import auth_service.entity.Usuario;
import auth_service.exception.InvalidRefreshTokenException;
import auth_service.repository.AuthSessionRepository;
import auth_service.repository.RefreshTokenRepository;
import auth_service.repository.UsuarioRepository;
import auth_service.repository.UsuarioRolRepository;
import auth_service.security.AuthPrincipal;
import auth_service.security.JwtService;
import auth_service.security.SessionTokens;
import auth_service.service.SessionTokenService;

@Service
public class PersistentSessionTokenService implements SessionTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_BYTES = 32;

    private final AuthSessionRepository authSessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UsuarioRepository usuarioRepository;
    private final UsuarioRolRepository usuarioRolRepository;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public PersistentSessionTokenService(
            AuthSessionRepository authSessionRepository,
            RefreshTokenRepository refreshTokenRepository,
            UsuarioRepository usuarioRepository,
            UsuarioRolRepository usuarioRolRepository,
            JwtService jwtService,
            JwtProperties jwtProperties) {
        this.authSessionRepository = authSessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.usuarioRepository = usuarioRepository;
        this.usuarioRolRepository = usuarioRolRepository;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
    }

    @Override
    @Transactional
    public SessionTokens startSession(Usuario usuario, Empresa empresa, List<String> roles) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime expiresAt = now.plusNanos(
                TimeUnit.MILLISECONDS.toNanos(jwtProperties.refreshExpirationMs()));
        UUID sessionId = UUID.randomUUID();
        AuthSession session = authSessionRepository.save(AuthSession.builder()
                .id(sessionId)
                .usuario(usuario)
                .empresa(empresa)
                .createdAt(now)
                .expiresAt(expiresAt)
                .build());

        String rawRefreshToken = newRefreshToken();
        RefreshToken refreshToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .authSession(session)
                .tokenHash(hashToken(rawRefreshToken))
                .createdAt(now)
                .expiresAt(expiresAt)
                .build();
        refreshTokenRepository.save(refreshToken);
        return createTokenPair(usuario.getId(), empresa.getId(), sessionId, roles,
                rawRefreshToken, jwtProperties.refreshExpirationMs());
    }

    @Override
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public SessionTokens rotate(String rawRefreshToken) {
        if (rawRefreshToken == null || !rawRefreshToken.matches("[A-Za-z0-9_-]{43}")) {
            throw new InvalidRefreshTokenException();
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        RefreshToken current = refreshTokenRepository
                .findByTokenHashForUpdate(hashToken(rawRefreshToken))
                .orElseThrow(InvalidRefreshTokenException::new);
        AuthSession session = current.getAuthSession();

        if (current.getRevokedAt() != null) {
            revokeSession(session, now);
            throw new InvalidRefreshTokenException();
        }
        if (session.getRevokedAt() != null || !current.getExpiresAt().isAfter(now)
                || !session.getExpiresAt().isAfter(now)) {
            revokeSession(session, now);
            throw new InvalidRefreshTokenException();
        }

        Usuario usuario = session.getUsuario();
        Empresa empresa = session.getEmpresa();
        if (!Boolean.TRUE.equals(usuario.getActivo()) || !Boolean.TRUE.equals(empresa.getActivo())) {
            revokeSession(session, now);
            throw new InvalidRefreshTokenException();
        }

        List<String> roles = usuarioRolRepository.findAllByUsuarioId(usuario.getId()).stream()
                .map(usuarioRol -> usuarioRol.getRol().getNombre())
                .toList();
        String nextRawToken = newRefreshToken();
        RefreshToken next = refreshTokenRepository.save(RefreshToken.builder()
                .id(UUID.randomUUID())
                .authSession(session)
                .tokenHash(hashToken(nextRawToken))
                .createdAt(now)
                .expiresAt(session.getExpiresAt())
                .build());

        current.setRevokedAt(now);
        current.setReplacedById(next.getId());
        refreshTokenRepository.save(current);

        return createTokenPair(
                usuario.getId(),
                empresa.getId(),
                session.getId(),
                roles,
                nextRawToken,
                Math.max(0, TimeUnit.NANOSECONDS.toMillis(
                        java.time.Duration.between(now, session.getExpiresAt()).toNanos())));
    }

    @Override
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public void revoke(AuthPrincipal principal) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        authSessionRepository.findByIdAndTenant(
                        principal.sessionId(), principal.usuarioId(), principal.empresaId())
                .ifPresent(session -> revokeSession(session, now));
    }

    @Override
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public void revokeAllForUser(AuthPrincipal principal) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        authSessionRepository.revokeAllForUserAndTenant(
                principal.usuarioId(), principal.empresaId(), now);
        refreshTokenRepository.revokeAllForUserAndTenant(
                principal.usuarioId(), principal.empresaId(), now);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isActive(AuthPrincipal principal) {
        return authSessionRepository.existsActiveSession(
                principal.sessionId(),
                principal.usuarioId(),
                principal.empresaId(),
                OffsetDateTime.now(ZoneOffset.UTC));
    }

    private void revokeSession(AuthSession session, OffsetDateTime revokedAt) {
        if (session.getRevokedAt() == null) {
            session.setRevokedAt(revokedAt);
            authSessionRepository.save(session);
        }
        refreshTokenRepository.revokeAllForSession(session.getId(), revokedAt);
    }

    private SessionTokens createTokenPair(
            UUID usuarioId,
            UUID empresaId,
            UUID sessionId,
            List<String> roles,
            String refreshToken,
            long refreshExpirationMs) {
        return new SessionTokens(
                usuarioId,
                empresaId,
                sessionId,
                jwtService.generarToken(usuarioId, empresaId, sessionId, roles),
                refreshToken,
                Math.ceilDiv(jwtProperties.expirationMs(), TimeUnit.SECONDS.toMillis(1)),
                Math.ceilDiv(refreshExpirationMs, TimeUnit.SECONDS.toMillis(1)));
    }

    private static String newRefreshToken() {
        byte[] randomBytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(randomBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private static String hashToken(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.US_ASCII));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime.", exception);
        }
    }
}
