package com.vaultix.authorization.service;

import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.vaultix.authorization.dto.admin.SigningKeyResponse;

public interface SigningKeyService {

    String ROTATION_TOPIC = "auth:signing-key:rotation";

    RSAKey getActiveSigningKey();

    JWKSet getJwkSet();

    Map<String, Object> getJwkSetAsMap();

    SigningKeyResponse rotateKey();

    int cleanExpiredKeys();

    void handleRotationEvent(String eventPayload);

    Page<SigningKeyResponse> getAllSigningKeys(Pageable pageable);
}
