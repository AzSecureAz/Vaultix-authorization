package com.vaultix.authorization.security.webauthn;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class RedisPublicKeyCredentialCreationOptionsRepository implements PublicKeyCredentialCreationOptionsRepository {

    public static final String REDIS_CHALLENGE_PREFIX = "auth:webauthn:challenge:";
    public static final String CHALLENGE_COOKIE_NAME = "VAULTIX_WEBAUTHN_CHALLENGE";
    public static final String CHALLENGE_HEADER_NAME = "X-WebAuthn-Challenge";
    public static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate stringRedisTemplate;

    public RedisPublicKeyCredentialCreationOptionsRepository(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    public void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialCreationOptions creationOptions) {
        if (creationOptions == null) {
            String challengeId = extractChallengeCookie(request);
            if (challengeId == null || challengeId.isBlank()) {
                challengeId = request != null ? request.getHeader(CHALLENGE_HEADER_NAME) : null;
            }
            if (challengeId != null && !challengeId.isBlank()) {
                stringRedisTemplate.delete(REDIS_CHALLENGE_PREFIX + challengeId);
            }
            if (response != null) {
                Cookie cookie = new Cookie(CHALLENGE_COOKIE_NAME, "");
                cookie.setHttpOnly(true);
                boolean isHttps = request != null && (request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")));
                cookie.setSecure(isHttps);
                cookie.setAttribute("SameSite", "Lax");
                String contextPath = request != null ? request.getContextPath() : null;
                cookie.setPath(contextPath != null && !contextPath.isBlank() ? contextPath : "/api/v1/auth");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
            return;
        }

        try {
            String payload = serialize(creationOptions);
            String challengeId = creationOptions.getChallenge().toBase64UrlString();

            /* Key solely by challenge ID: exactly one entry in Redis */
            String challengeKey = REDIS_CHALLENGE_PREFIX + challengeId;
            stringRedisTemplate.opsForValue().set(challengeKey, payload, CHALLENGE_TTL);

            /* Set short-lived challenge cookie */
            Cookie cookie = new Cookie(CHALLENGE_COOKIE_NAME, challengeId);
            cookie.setHttpOnly(true);
            boolean isHttps = request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
            cookie.setSecure(isHttps);
            cookie.setAttribute("SameSite", "Lax");
            String contextPath = request.getContextPath();
            cookie.setPath(contextPath != null && !contextPath.isBlank() ? contextPath : "/api/v1/auth");
            cookie.setMaxAge((int) CHALLENGE_TTL.toSeconds());
            response.addCookie(cookie);

            /* Expose response header for clients */
            response.setHeader(CHALLENGE_HEADER_NAME, challengeId);

            log.debug("Saved WebAuthn PublicKeyCredentialCreationOptions to Redis with challengeId: {}", challengeId);
        } catch (DataAccessException | IllegalStateException e) {
            log.error("Failed to serialize and save PublicKeyCredentialCreationOptions to Redis", e);
            throw new IllegalStateException("Failed to persist WebAuthn registration challenge", e);
        }
    }

    @Override
    public PublicKeyCredentialCreationOptions load(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        /* 1. Try to find challenge from cookie */
        String challengeId = extractChallengeCookie(request);

        /* 2. Fallback to header */
        if (challengeId == null || challengeId.isBlank()) {
            challengeId = request.getHeader(CHALLENGE_HEADER_NAME);
        }

        if (challengeId == null || challengeId.isBlank()) {
            log.warn("No WebAuthn creation options found in Redis for registration request");
            return null;
        }

        String challengeKey = REDIS_CHALLENGE_PREFIX + challengeId;
        String payload = stringRedisTemplate.opsForValue().get(challengeKey);

        if (payload == null) {
            log.warn("WebAuthn creation options expired or not found in Redis for challengeId: {}", challengeId);
            return null;
        }

        PublicKeyCredentialCreationOptions options = deserialize(payload);

        /* One-time use: clean up from Redis */
        stringRedisTemplate.delete(challengeKey);

        return options;
    }

    private String serialize(PublicKeyCredentialCreationOptions creationOptions) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(creationOptions);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize PublicKeyCredentialCreationOptions", e);
        }
    }

    private PublicKeyCredentialCreationOptions deserialize(String base64) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(base64));
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (PublicKeyCredentialCreationOptions) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            log.error("Failed to deserialize PublicKeyCredentialCreationOptions from Redis payload", e);
            return null;
        }
    }

    private String extractChallengeCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        return Arrays.stream(request.getCookies())
                .filter(c -> CHALLENGE_COOKIE_NAME.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
