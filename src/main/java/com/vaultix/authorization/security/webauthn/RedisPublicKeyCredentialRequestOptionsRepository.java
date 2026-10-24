package com.vaultix.authorization.security.webauthn;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
@Component
public class RedisPublicKeyCredentialRequestOptionsRepository implements PublicKeyCredentialRequestOptionsRepository {

    public static final String REDIS_AUTH_CHALLENGE_PREFIX = "auth:webauthn:auth-challenge:";
    public static final String AUTH_CHALLENGE_COOKIE_NAME = "VAULTIX_WEBAUTHN_AUTH_CHALLENGE";
    public static final String AUTH_CHALLENGE_HEADER_NAME = "X-WebAuthn-Challenge";
    public static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate stringRedisTemplate;
    private final JsonMapper jsonMapper;

    public RedisPublicKeyCredentialRequestOptionsRepository(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.jsonMapper = JsonMapper.builder()
                .addModule(new WebauthnJacksonModule())
                .build();
    }

    @Override
    public void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialRequestOptions requestOptions) {
        if (requestOptions == null) {
            String challengeId = extractChallengeCookie(request);
            if (challengeId == null || challengeId.isBlank()) {
                challengeId = request != null ? request.getHeader(AUTH_CHALLENGE_HEADER_NAME) : null;
            }
            if (challengeId != null && !challengeId.isBlank()) {
                stringRedisTemplate.delete(REDIS_AUTH_CHALLENGE_PREFIX + challengeId);
            }
            if (response != null) {
                Cookie cookie = new Cookie(AUTH_CHALLENGE_COOKIE_NAME, "");
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
            String json = jsonMapper.writeValueAsString(requestOptions);
            String challengeId = requestOptions.getChallenge().toBase64UrlString();

            /* Key by challenge ID in Redis */
            String challengeKey = REDIS_AUTH_CHALLENGE_PREFIX + challengeId;
            stringRedisTemplate.opsForValue().set(challengeKey, json, CHALLENGE_TTL);

            /* Attach challenge cookie for browser sessions */
            Cookie cookie = new Cookie(AUTH_CHALLENGE_COOKIE_NAME, challengeId);
            cookie.setHttpOnly(true);
            boolean isHttps = request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
            cookie.setSecure(isHttps);
            cookie.setAttribute("SameSite", "Lax");
            String contextPath = request.getContextPath();
            cookie.setPath(contextPath != null && !contextPath.isBlank() ? contextPath : "/api/v1/auth");
            cookie.setMaxAge((int) CHALLENGE_TTL.toSeconds());
            response.addCookie(cookie);

            /* Also expose response header for mobile/API clients */
            response.setHeader(AUTH_CHALLENGE_HEADER_NAME, challengeId);

            log.debug("Saved WebAuthn PublicKeyCredentialRequestOptions to Redis with challengeId: {}", challengeId);
        } catch (JacksonException | DataAccessException e) {
            log.error("Failed to serialize and save PublicKeyCredentialRequestOptions to Redis", e);
            throw new IllegalStateException("Failed to persist WebAuthn authentication challenge", e);
        }
    }

    @Override
    public PublicKeyCredentialRequestOptions load(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        /* 1. Try to extract challenge ID from cookie */
        String challengeId = extractChallengeCookie(request);

        /* 2. Fallback to request header for API / mobile clients */
        if (challengeId == null || challengeId.isBlank()) {
            challengeId = request.getHeader(AUTH_CHALLENGE_HEADER_NAME);
        }

        if (challengeId == null || challengeId.isBlank()) {
            log.warn("No WebAuthn authentication challenge identifier found in cookie or header");
            return null;
        }

        String redisKey = REDIS_AUTH_CHALLENGE_PREFIX + challengeId;
        String json = stringRedisTemplate.opsForValue().get(redisKey);

        if (json == null) {
            log.warn("WebAuthn authentication challenge expired or not found in Redis for challengeId: {}", challengeId);
            return null;
        }

        try {
            PublicKeyCredentialRequestOptions options = jsonMapper.readValue(json, PublicKeyCredentialRequestOptions.class);

            /* Single-use challenge: evict immediately upon retrieval to prevent replay attacks */
            stringRedisTemplate.delete(redisKey);

            return options;
        } catch (JacksonException | DataAccessException e) {
            log.error("Failed to deserialize PublicKeyCredentialRequestOptions from Redis", e);
            return null;
        }
    }

    private String extractChallengeCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        return Arrays.stream(request.getCookies())
                .filter(c -> AUTH_CHALLENGE_COOKIE_NAME.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
