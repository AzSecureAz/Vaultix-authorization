package com.vaultix.authorization.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.SigningKey;
import com.vaultix.authorization.entity.enums.KeyStatus;

@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

    Optional<SigningKey> findByStatus(KeyStatus status);

    @Query("SELECT k FROM SigningKey k WHERE k.status = com.vaultix.authorization.entity.enums.KeyStatus.ACTIVE OR (k.status = com.vaultix.authorization.entity.enums.KeyStatus.ROTATED AND k.updatedAt >= :threshold)")
    List<SigningKey> findActiveAndValidRotatedKeys(@Param("threshold") Instant threshold);
}
