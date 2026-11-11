package auth_service.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import auth_service.entity.AuthSession;

public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {

    @Query("""
            select count(session) > 0
            from AuthSession session
            where session.id = :sessionId
              and session.usuario.id = :usuarioId
              and session.empresa.id = :empresaId
              and session.revokedAt is null
              and session.expiresAt > :now
              and session.usuario.activo = true
              and session.empresa.activo = true
            """)
    boolean existsActiveSession(
            @Param("sessionId") UUID sessionId,
            @Param("usuarioId") UUID usuarioId,
            @Param("empresaId") UUID empresaId,
            @Param("now") OffsetDateTime now);

    @Query("""
            select session
            from AuthSession session
            where session.id = :sessionId
              and session.usuario.id = :usuarioId
              and session.empresa.id = :empresaId
            """)
    Optional<AuthSession> findByIdAndTenant(
            @Param("sessionId") UUID sessionId,
            @Param("usuarioId") UUID usuarioId,
            @Param("empresaId") UUID empresaId);

    @Modifying
    @Query("""
            update AuthSession session
            set session.revokedAt = :revokedAt
            where session.usuario.id = :usuarioId
              and session.empresa.id = :empresaId
              and session.revokedAt is null
            """)
    int revokeAllForUserAndTenant(
            @Param("usuarioId") UUID usuarioId,
            @Param("empresaId") UUID empresaId,
            @Param("revokedAt") OffsetDateTime revokedAt);
}
