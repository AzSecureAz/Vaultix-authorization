package com.vaultix.authorization.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.SigningKey;
import com.vaultix.authorization.entity.enums.KeyStatus;

@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

    Optional<SigningKey> findByStatus(KeyStatus status);

    Optional<SigningKey> findByKid(String kid);

    @Query("SELECT k FROM SigningKey k WHERE k.status = com.vaultix.authorization.entity.enums.KeyStatus.ACTIVE OR (k.status = com.vaultix.authorization.entity.enums.KeyStatus.ROTATED AND k.updatedAt >= :threshold)")
    List<SigningKey> findActiveAndValidRotatedKeys(@Param("threshold") Instant threshold);

    @Modifying
    @Query(value = """
            DELETE FROM signing_keys
            WHERE id IN (
                SELECT id FROM signing_keys
                WHERE (status = 'REVOKED' AND updated_at < :revokedThreshold)
                   OR (status = 'ROTATED' AND updated_at < :rotatedThreshold)
                LIMIT :limit
            )
            """, nativeQuery = true)
    int deleteExpiredSigningKeysBatch(
            @Param("revokedThreshold") Instant revokedThreshold,
            @Param("rotatedThreshold") Instant rotatedThreshold,
            @Param("limit") int limit);
}
