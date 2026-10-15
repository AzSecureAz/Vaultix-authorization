package com.vaultix.authorization.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.SigningKey;

@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

}
