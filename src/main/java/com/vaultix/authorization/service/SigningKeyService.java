package com.vaultix.authorization.service;

import java.util.Map;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.vaultix.authorization.dto.admin.SigningKeyResponse;

public interface SigningKeyService {

    String ROTATION_TOPIC = "auth:signing-key:rotation";
    String REVOCATION_TOPIC = "auth:signing-key:revocation";

    RSAKey getActiveSigningKey();

    JWKSet getJwkSet();

    Map<String, Object> getJwkSetAsMap();

    SigningKeyResponse rotateKey();

    SigningKeyResponse rotateKey(UUID actorId);

    int cleanExpiredKeys();

    void handleRotationEvent(String eventPayload);

    void handleRevocationEvent(String eventPayload);

    Page<SigningKeyResponse> getAllSigningKeys(Pageable pageable);

    SigningKeyResponse getKeyByKid(String kid);

    SigningKeyResponse revokeKey(String kid, UUID actorId);
}
