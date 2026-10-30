package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.dto.SessionResponse;
import com.vaultix.authorization.entity.RefreshToken;
import com.vaultix.authorization.repository.RefreshTokenRepository;
import com.vaultix.authorization.service.SessionService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.security.TokenBlacklistService;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class SessionServiceImpl implements SessionService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistService tokenBlacklistService;
    private final TokenService tokenService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional(readOnly = true)
    public SessionResponse getCurrentSession(
            @NotNull(message = "Current access token JTI is required") UUID currentAccessTokenJti) {

        log.debug("Fetching current session for token JTI: {}", currentAccessTokenJti);

        Optional<RefreshToken> sessionOpt = refreshTokenRepository.findByAccessTokenJti(currentAccessTokenJti);
        if (sessionOpt.isEmpty()) {
            sessionOpt = refreshTokenRepository.findWithUserAndRolesAndPermissionsByRefreshTokenJti(currentAccessTokenJti);
        }

        RefreshToken session = sessionOpt.orElseThrow(
                () -> new ResourceNotFoundException("Active session not found for provided token"));

        if (session.isRevoked() || session.getExpiresAt().isBefore(Instant.now())) {
            throw new ResourceNotFoundException("Current session has been revoked or expired");
        }

        return SessionResponse.fromEntity(session, currentAccessTokenJti);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<SessionResponse> getOtherActiveSessions(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Current access token JTI is required") UUID currentAccessTokenJti,
            Pageable pageable) {

        Pageable page = (pageable != null && pageable.isPaged())
                ? (pageable.getPageSize() > 50
                ? PageRequest.of(pageable.getPageNumber(), 50, pageable.getSort())
                : pageable)
                : PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "createdAt"));

        log.debug("Fetching other active sessions for user ID: {} excluding JTI: {}, pageable: {}", userId, currentAccessTokenJti, page);

        Page<RefreshToken> sessions = refreshTokenRepository.findActiveSessionsByUserIdExcludingCurrent(
                userId, currentAccessTokenJti, Instant.now(), page);

        return sessions.map(session -> SessionResponse.fromEntity(session, currentAccessTokenJti));
    }

    @Override
    @Transactional
    public void revokeSession(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Session ID cannot be null") UUID sessionId) {

        log.info("Revoking session ID: {} for user ID: {}", sessionId, userId);

        RefreshToken session = refreshTokenRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found with ID: " + sessionId));

        if (!session.getUser().getId().equals(userId)) {
            throw new ResourceNotFoundException("Session not found with ID: " + sessionId);
        }

        if (session.isRevoked()) {
            log.info("Session ID: {} is already revoked", sessionId);
            return;
        }

        session.setRevoked(true);
        session.setRevokedAt(Instant.now());
        refreshTokenRepository.save(session);

        if (session.getAccessTokenJti() != null) {
            tokenBlacklistService.blacklist(session.getAccessTokenJti().toString(), jwtProperties.accessTokenExpiration());
        }

        log.info("Successfully revoked session ID: {} for user ID: {}", sessionId, userId);
    }

    @Override
    @Transactional
    public int revokeOtherSessions(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Current access token JTI is required") UUID currentAccessTokenJti) {

        log.info("Revoking other sessions for user ID: {} excluding current token JTI: {}", userId, currentAccessTokenJti);
        return tokenService.revokeOtherUserTokens(userId, currentAccessTokenJti);
    }

    @Override
    @Transactional
    public int revokeAllSessions(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Revoking all sessions for user ID: {}", userId);
        return tokenService.revokeAllUserTokens(userId);
    }
}
