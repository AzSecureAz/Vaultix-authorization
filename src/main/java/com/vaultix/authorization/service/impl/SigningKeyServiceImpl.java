package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.config.properties.KekProperties;
import com.vaultix.authorization.entity.SigningKey;
import com.vaultix.authorization.entity.enums.KeyStatus;
import com.vaultix.authorization.repository.SigningKeyRepository;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.crypto.AesGcmCryptoUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class SigningKeyServiceImpl implements SigningKeyService, ApplicationRunner {

    private final SigningKeyRepository signingKeyRepository;
    private final KekProperties kekProperties;
    private final JwtProperties jwtProperties;
    private final StringRedisTemplate stringRedisTemplate;

    private final Cache<String, RSAKey> activeKeyCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(1)
            .build();

    private final Cache<String, JWKSet> jwkSetCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(1)
            .build();

    @Override
    public void run(ApplicationArguments args) {
        log.info("Checking RSA signing key on startup...");
        RSAKey activeKey = getActiveSigningKey();
        log.info("Active RSA signing key ready with kid: {}", activeKey.getKeyID());
    }

    @Override
    public RSAKey getActiveSigningKey() {
        return activeKeyCache.get("active", key -> signingKeyRepository.findByStatus(KeyStatus.ACTIVE)
                .map(entity -> toRsaKey(entity, true))
                .orElseGet(this::createAndSaveNewActiveKey));
    }

    @Override
    public JWKSet getJwkSet() {
        return jwkSetCache.get("jwks", key -> {
            Instant threshold = Instant.now().minus(jwtProperties.refreshTokenExpiration());
            List<SigningKey> keys = signingKeyRepository.findActiveAndValidRotatedKeys(threshold);
            List<JWK> jwkList = keys.stream()
                    .map(entity -> (JWK) toRsaKey(entity, false).toPublicJWK())
                    .toList();
            return new JWKSet(jwkList);
        });
    }

    @Override
    public Map<String, Object> getJwkSetAsMap() {
        return getJwkSet().toJSONObject();
    }

    @Override
    @Transactional
    public RSAKey rotateKey() {
        log.info("Initiating RSA signing key rotation...");

        signingKeyRepository.findByStatus(KeyStatus.ACTIVE).ifPresent(currentKey -> {
            currentKey.setStatus(KeyStatus.ROTATED);
            signingKeyRepository.save(currentKey);
            log.info("Marked previous active key as ROTATED. kid: {}", currentKey.getKid());
        });

        RSAKey newKey = createAndSaveNewActiveKey();

        activeKeyCache.invalidateAll();
        jwkSetCache.invalidateAll();

        activeKeyCache.put("active", newKey);
        log.info("Successfully rotated signing key locally. New active kid: {}", newKey.getKeyID());

        try {
            String payload = "KEY_ROTATED:" + newKey.getKeyID();
            stringRedisTemplate.convertAndSend(ROTATION_TOPIC, payload);
            log.info("Broadcasted key rotation event to Redis topic '{}': {}", ROTATION_TOPIC, payload);
        } catch (Exception e) {
            log.warn("Failed to publish key rotation event to Redis. Other instances will sync on cache TTL expiry", e);
        }

        return newKey;
    }

    @Override
    public void handleRotationEvent(String eventPayload) {
        log.info("Received key rotation notification from Redis: {}. Invalidating local caches...", eventPayload);
        activeKeyCache.invalidateAll();
        jwkSetCache.invalidateAll();
        try {
            RSAKey activeKey = getActiveSigningKey();
            log.info("Local caches refreshed with new active key: {}", activeKey.getKeyID());
        } catch (Exception e) {
            log.warn("Failed to eagerly reload active key after rotation notification", e);
        }
    }

    private RSAKey createAndSaveNewActiveKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            String publicKeyPem = toPem(publicKey.getEncoded(), "PUBLIC KEY");
            String privateKeyPem = toPem(privateKey.getEncoded(), "PRIVATE KEY");

            String encryptedPrivateKey = AesGcmCryptoUtil.encrypt(privateKeyPem, kekProperties.masterKey());
            String kid = "vaultix-" + UUID.randomUUID();

            SigningKey signingKey = SigningKey.builder()
                    .kid(kid)
                    .algorithm("RS256")
                    .keyUse("sig")
                    .publicKeyPem(publicKeyPem)
                    .encryptedPrivateKey(encryptedPrivateKey)
                    .status(KeyStatus.ACTIVE)
                    .build();

            signingKeyRepository.save(signingKey);
            log.info("Generated and persisted new active RSA signing key with kid: {}", kid);

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate RSA keypair", e);
        }
    }

    private RSAKey toRsaKey(SigningKey entity, boolean includePrivate) {
        RSAPublicKey publicKey = parsePublicKey(entity.getPublicKeyPem());
        RSAKey.Builder builder = new RSAKey.Builder(publicKey)
                .keyID(entity.getKid())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256);

        if (includePrivate) {
            String decryptedPrivateKeyPem = AesGcmCryptoUtil.decrypt(
                    entity.getEncryptedPrivateKey(),
                    kekProperties.masterKey()
            );
            RSAPrivateKey privateKey = parsePrivateKey(decryptedPrivateKeyPem);
            builder.privateKey(privateKey);
        }

        return builder.build();
    }

    private String toPem(byte[] encodedKey, String headerFooter) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(encodedKey);
        return "-----BEGIN " + headerFooter + "-----\n" + base64 + "\n-----END " + headerFooter + "-----";
    }

    private RSAPublicKey parsePublicKey(String pem) {
        try {
            String sanitized = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(sanitized);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to parse RSA public key from PEM", e);
        }
    }

    private RSAPrivateKey parsePrivateKey(String pem) {
        try {
            String sanitized = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(sanitized);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to parse RSA private key from PEM", e);
        }
    }
}
