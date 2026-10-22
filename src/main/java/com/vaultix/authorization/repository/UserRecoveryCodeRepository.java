package com.vaultix.authorization.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.UserRecoveryCode;

@Repository
public interface UserRecoveryCodeRepository extends JpaRepository<UserRecoveryCode, UUID> {

    void deleteByUserId(UUID userId);

    boolean existsByUserIdAndUsedFalse(UUID userId);

    Optional<UserRecoveryCode> findByUserIdAndCodeHashAndUsedFalse(UUID userId, String codeHash);

    long countByUserIdAndUsedFalse(UUID userId);
}
