package com.vaultix.authorization.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.UserTotp;

@Repository
public interface UserTotpRepository extends JpaRepository<UserTotp, UUID> {

    Optional<UserTotp> findByUserId(UUID userId);
}
