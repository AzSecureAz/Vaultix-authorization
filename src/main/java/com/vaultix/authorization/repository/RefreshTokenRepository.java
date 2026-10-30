package com.vaultix.authorization.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @EntityGraph(attributePaths = {"user", "user.roles", "user.roles.permissions"})
    Optional<RefreshToken> findWithUserAndRolesAndPermissionsByRefreshTokenJti(UUID refreshTokenJti);

    Optional<RefreshToken> findByAccessTokenJti(UUID accessTokenJti);

    @Query("SELECT r.accessTokenJti FROM RefreshToken r WHERE r.user.id = :userId AND r.revoked = false AND r.expiresAt > :now")
    List<UUID> findActiveAccessTokenJtisByUserId(@Param("userId") UUID userId, @Param("now") Instant now);

    @Query("SELECT r.accessTokenJti FROM RefreshToken r WHERE r.user.id = :userId AND r.accessTokenJti <> :currentJti AND r.revoked = false AND r.expiresAt > :now")
    List<UUID> findActiveAccessTokenJtisByUserIdExcludingCurrent(
            @Param("userId") UUID userId,
            @Param("currentJti") UUID currentJti,
            @Param("now") Instant now);

    @Query("SELECT r FROM RefreshToken r WHERE r.user.id = :userId AND r.accessTokenJti <> :currentJti AND r.revoked = false AND r.expiresAt > :now")
    Page<RefreshToken> findActiveSessionsByUserIdExcludingCurrent(
            @Param("userId") UUID userId,
            @Param("currentJti") UUID currentJti,
            @Param("now") Instant now,
            Pageable pageable);

    @Modifying
    @Query(value = """
            DELETE FROM refresh_tokens
            WHERE id IN (
                SELECT id FROM refresh_tokens
                WHERE revoked_at < :revokedThreshold
                   OR expires_at < :expiredThreshold
                LIMIT :limit
            )
            """, nativeQuery = true)
    int deleteExpiredTokensBatch(
            @Param("revokedThreshold") Instant revokedThreshold,
            @Param("expiredThreshold") Instant expiredThreshold,
            @Param("limit") int limit);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true, r.revokedAt = :now WHERE r.accessTokenJti IN :jtis")
    int revokeByAccessTokenJtis(@Param("jtis") List<UUID> jtis, @Param("now") Instant now);
}
