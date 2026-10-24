package com.vaultix.authorization.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.UserPasskeyCredential;

@Repository
public interface UserPasskeyCredentialRepository extends JpaRepository<UserPasskeyCredential, UUID> {

    Optional<UserPasskeyCredential> findByCredentialId(String credentialId);

    List<UserPasskeyCredential> findByUserEntityUserId(String userEntityUserId);

    List<UserPasskeyCredential> findByUserIdOrderByCreatedAtDesc(UUID userId);

    Optional<UserPasskeyCredential> findByIdAndUserId(UUID id, UUID userId);

    long countByUserId(UUID userId);
}
