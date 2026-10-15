package com.vaultix.authorization.service;

import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

public interface SigningKeyService {

    String ROTATION_TOPIC = "auth:signing-key:rotation";

    RSAKey getActiveSigningKey();

    JWKSet getJwkSet();

    Map<String, Object> getJwkSetAsMap();

    RSAKey rotateKey();

    void handleRotationEvent(String eventPayload);
}
