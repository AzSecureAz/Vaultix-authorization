package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.OtpProperties;
import com.vaultix.authorization.service.OtpService;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private static final String REDIS_OTP_PREFIX = "auth:otp:";
    private static final String FIELD_HASH = "hash";
    private static final String FIELD_ATTEMPTS = "attempts";

    private final StringRedisTemplate stringRedisTemplate;
    private final OtpProperties otpProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generateOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier,
            Duration ttl) {

        String cleanPurpose = purpose.strip().toLowerCase(Locale.ROOT);
        String cleanIdentifier = identifier.strip().toLowerCase(Locale.ROOT);
        Duration effectiveTtl = (ttl != null && !ttl.isNegative() && !ttl.isZero()) ? ttl : otpProperties.defaultTtl();

        int length = otpProperties.length();
        int min = (int) Math.pow(10, length - 1);
        int bound = (int) Math.pow(10, length) - min;
        int code = min + secureRandom.nextInt(bound);
        String rawOtp = String.valueOf(code);

        String hash = hashOtp(cleanPurpose, cleanIdentifier, rawOtp);
        String redisKey = buildKey(cleanPurpose, cleanIdentifier);

        stringRedisTemplate.opsForHash().put(redisKey, FIELD_HASH, hash);
        stringRedisTemplate.opsForHash().put(redisKey, FIELD_ATTEMPTS, "0");
        stringRedisTemplate.expire(redisKey, effectiveTtl);

        log.info("Generated OTP for purpose '{}' and identifier '{}' with TTL {}s", cleanPurpose, cleanIdentifier, effectiveTtl.toSeconds());
        return rawOtp;
    }

    @Override
    public String generateOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier) {

        return generateOtp(purpose, identifier, null);
    }

    @Override
    public boolean verifyOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier,
            @NotBlank(message = "Candidate OTP is required")
            @Size(max = 16, message = "Candidate OTP cannot exceed 16 characters") String candidateOtp) {

        String cleanPurpose = purpose.strip().toLowerCase(Locale.ROOT);
        String cleanIdentifier = identifier.strip().toLowerCase(Locale.ROOT);
        String redisKey = buildKey(cleanPurpose, cleanIdentifier);

        Map<Object, Object> data = stringRedisTemplate.opsForHash().entries(redisKey);
        if (data == null || data.isEmpty()) {
            log.warn("OTP verification failed: no active OTP found for purpose '{}' and identifier '{}'", cleanPurpose, cleanIdentifier);
            return false;
        }

        String storedHash = (String) data.get(FIELD_HASH);
        String attemptsStr = (String) data.get(FIELD_ATTEMPTS);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;

        if (attempts >= otpProperties.maxAttempts()) {
            stringRedisTemplate.delete(redisKey);
            log.warn("OTP locked out: max attempts ({}) exceeded for purpose '{}' and identifier '{}'",
                    otpProperties.maxAttempts(), cleanPurpose, cleanIdentifier);
            return false;
        }

        String candidateHash = hashOtp(cleanPurpose, cleanIdentifier, candidateOtp.strip());
        byte[] storedBytes = storedHash != null ? storedHash.getBytes(StandardCharsets.UTF_8) : new byte[0];
        byte[] candidateBytes = candidateHash.getBytes(StandardCharsets.UTF_8);

        if (MessageDigest.isEqual(storedBytes, candidateBytes)) {
            stringRedisTemplate.delete(redisKey);
            log.info("OTP verified successfully for purpose '{}' and identifier '{}'", cleanPurpose, cleanIdentifier);
            return true;
        } else {
            Long newAttempts = stringRedisTemplate.opsForHash().increment(redisKey, FIELD_ATTEMPTS, 1);
            log.warn("OTP verification failed for purpose '{}' and identifier '{}'. Attempt {}/{}",
                    cleanPurpose, cleanIdentifier, newAttempts, otpProperties.maxAttempts());
            if (newAttempts != null && newAttempts >= otpProperties.maxAttempts()) {
                stringRedisTemplate.delete(redisKey);
                log.warn("OTP invalidated: max attempts reached for purpose '{}' and identifier '{}'", cleanPurpose, cleanIdentifier);
            }
            return false;
        }
    }

    @Override
    public void clearOtp(
            @NotBlank(message = "Purpose is required")
            @Size(max = 64, message = "Purpose cannot exceed 64 characters") String purpose,
            @NotBlank(message = "Identifier is required")
            @Size(max = 256, message = "Identifier cannot exceed 256 characters") String identifier) {

        String cleanPurpose = purpose.strip().toLowerCase(Locale.ROOT);
        String cleanIdentifier = identifier.strip().toLowerCase(Locale.ROOT);
        stringRedisTemplate.delete(buildKey(cleanPurpose, cleanIdentifier));
        log.info("Cleared OTP for purpose '{}' and identifier '{}'", cleanPurpose, cleanIdentifier);
    }

    private String buildKey(String purpose, String identifier) {
        return REDIS_OTP_PREFIX + purpose + ":" + identifier;
    }

    private String hashOtp(String purpose, String identifier, String otp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String payload = purpose + ":" + identifier + ":" + otp;
            byte[] hashBytes = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest algorithm unavailable", e);
        }
    }
}
