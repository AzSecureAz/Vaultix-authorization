package com.vaultix.authorization.security.webauthn;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
@Component
public class RedisPublicKeyCredentialCreationOptionsRepository implements PublicKeyCredentialCreationOptionsRepository {

    public static final String REDIS_CHALLENGE_PREFIX = "auth:webauthn:challenge:";
    public static final String CHALLENGE_COOKIE_NAME = "VAULTIX_WEBAUTHN_CHALLENGE";
    public static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate stringRedisTemplate;
    private final JsonMapper jsonMapper;

    public RedisPublicKeyCredentialCreationOptionsRepository(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.jsonMapper = JsonMapper.builder()
                .addModule(new WebauthnJacksonModule())
                .build();
    }

    @Override
    public void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialCreationOptions creationOptions) {
        if (creationOptions == null) {
            return;
        }

        try {
            String json = jsonMapper.writeValueAsString(creationOptions);
            String challengeId = creationOptions.getChallenge().toBase64UrlString();

            /* Key by challenge ID */
            String challengeKey = REDIS_CHALLENGE_PREFIX + challengeId;
            stringRedisTemplate.opsForValue().set(challengeKey, json, CHALLENGE_TTL);

            /* Also key by authenticated user name/id if present */
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                String userKey = REDIS_CHALLENGE_PREFIX + "user:" + auth.getName();
                stringRedisTemplate.opsForValue().set(userKey, json, CHALLENGE_TTL);
            }

            /* Set short-lived challenge cookie */
            Cookie cookie = new Cookie(CHALLENGE_COOKIE_NAME, challengeId);
            cookie.setHttpOnly(true);
            boolean isHttps = request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
            cookie.setSecure(isHttps);
            cookie.setAttribute("SameSite", "Lax");
            cookie.setPath("/api/v1/auth");
            cookie.setMaxAge((int) CHALLENGE_TTL.toSeconds());
            response.addCookie(cookie);

            log.debug("Saved WebAuthn PublicKeyCredentialCreationOptions to Redis with TTL: {}", CHALLENGE_TTL);
        } catch (JacksonException | DataAccessException e) {
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
        String json = null;
        String resolvedKey = null;

        if (challengeId != null && !challengeId.isBlank()) {
            String challengeKey = REDIS_CHALLENGE_PREFIX + challengeId;
            json = stringRedisTemplate.opsForValue().get(challengeKey);
            if (json != null) {
                resolvedKey = challengeKey;
            }
        }

        /* 2. Fallback to authenticated user principal */
        if (json == null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                String userKey = REDIS_CHALLENGE_PREFIX + "user:" + auth.getName();
                json = stringRedisTemplate.opsForValue().get(userKey);
                if (json != null) {
                    resolvedKey = userKey;
                }
            }
        }

        if (json == null) {
            log.warn("No WebAuthn creation options found in Redis for registration request");
            return null;
        }

        try {
            PublicKeyCredentialCreationOptions options = jsonMapper.readValue(json, PublicKeyCredentialCreationOptions.class);

            /* One-time use: clean up from Redis */
            if (resolvedKey != null) {
                stringRedisTemplate.delete(resolvedKey);
            }
            if (challengeId != null) {
                stringRedisTemplate.delete(REDIS_CHALLENGE_PREFIX + challengeId);
            }
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                stringRedisTemplate.delete(REDIS_CHALLENGE_PREFIX + "user:" + auth.getName());
            }

            return options;
        } catch (JacksonException | DataAccessException e) {
            log.error("Failed to deserialize PublicKeyCredentialCreationOptions from Redis", e);
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
