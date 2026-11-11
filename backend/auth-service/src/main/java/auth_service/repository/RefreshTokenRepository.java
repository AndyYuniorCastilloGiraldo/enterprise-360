package auth_service.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import auth_service.entity.RefreshToken;
import jakarta.persistence.LockModeType;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from RefreshToken token where token.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Modifying
    @Query("""
            update RefreshToken token
            set token.revokedAt = :revokedAt
            where token.authSession.id = :sessionId
              and token.revokedAt is null
            """)
    int revokeAllForSession(
            @Param("sessionId") UUID sessionId,
            @Param("revokedAt") OffsetDateTime revokedAt);

    @Modifying
    @Query("""
            update RefreshToken token
            set token.revokedAt = :revokedAt
            where token.authSession.usuario.id = :usuarioId
              and token.authSession.empresa.id = :empresaId
              and token.revokedAt is null
            """)
    int revokeAllForUserAndTenant(
            @Param("usuarioId") UUID usuarioId,
            @Param("empresaId") UUID empresaId,
            @Param("revokedAt") OffsetDateTime revokedAt);

}
