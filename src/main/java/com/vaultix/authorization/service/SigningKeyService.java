package com.vaultix.authorization.service;

import java.util.Map;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.vaultix.authorization.dto.admin.SigningKeyResponse;
import com.vaultix.common.constant.SecurityTopics;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Validated
public interface SigningKeyService {

    String ROTATION_TOPIC = "auth:signing-key:rotation";
    String REVOCATION_TOPIC = SecurityTopics.SIGNING_KEY_REVOCATION;

    RSAKey getActiveSigningKey();

    JWKSet getJwkSet();

    Map<String, Object> getJwkSetAsMap();

    SigningKeyResponse rotateKey();

    SigningKeyResponse rotateKey(UUID actorId);

    int cleanExpiredKeys();

    void handleRotationEvent(String eventPayload);

    void handleRevocationEvent(String eventPayload);

    Page<SigningKeyResponse> getAllSigningKeys(Pageable pageable);

    SigningKeyResponse getKeyByKid(
            @NotBlank(message = "Key ID is required")
            @Size(max = 64, message = "Key ID cannot exceed 64 characters") String kid);

    SigningKeyResponse revokeKey(
            @NotBlank(message = "Key ID is required")
            @Size(max = 64, message = "Key ID cannot exceed 64 characters") String kid,
            @NotNull(message = "Actor ID cannot be null") UUID actorId);
}
