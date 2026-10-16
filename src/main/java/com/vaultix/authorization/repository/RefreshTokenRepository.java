package com.vaultix.authorization.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

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
}
