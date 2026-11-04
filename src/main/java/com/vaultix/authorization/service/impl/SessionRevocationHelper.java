package com.vaultix.authorization.service.impl;

import java.time.Instant;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.entity.RefreshToken;
import com.vaultix.authorization.repository.RefreshTokenRepository;
import com.vaultix.common.security.TokenBlacklistService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class SessionRevocationHelper {

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtProperties jwtProperties;

    /**
     * Immediately revokes a session in PostgreSQL and blacklists its access
     * token in Redis within an isolated, independent physical transaction
     * (REQUIRES_NEW).
     *
     * This guarantees that the revocation is permanently committed to
     * PostgreSQL even when the calling method subsequently throws an exception
     * (e.g. BadCredentialsException) which causes the outer transaction to roll
     * back.
     *
     * @param session the refresh token session entity to revoke
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeSessionImmediately(RefreshToken session) {
        if (session == null || session.getId() == null) {
            return;
        }

        Instant now = Instant.now();
        session.setRevoked(true);
        session.setRevokedAt(now);

        refreshTokenRepository.revokeById(session.getId(), now);

        if (session.getAccessTokenJti() != null) {
            tokenBlacklistService.blacklist(session.getAccessTokenJti().toString(), jwtProperties.accessTokenExpiration());
        }

        log.info("Committed immediate session revocation (REQUIRES_NEW) for session ID: {}, refresh token JTI: {}",
                session.getId(), session.getRefreshTokenJti());
    }
}
