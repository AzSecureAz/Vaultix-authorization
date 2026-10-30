package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.SessionResponse;

import jakarta.validation.constraints.NotNull;

@Validated
public interface SessionService {

    SessionResponse getCurrentSession(
            @NotNull(message = "Current access token JTI is required") UUID currentAccessTokenJti);

    Page<SessionResponse> getOtherActiveSessions(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Current access token JTI is required") UUID currentAccessTokenJti,
            Pageable pageable);

    void revokeSession(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Session ID cannot be null") UUID sessionId);

    int revokeOtherSessions(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Current access token JTI is required") UUID currentAccessTokenJti);

    int revokeAllSessions(
            @NotNull(message = "User ID cannot be null") UUID userId);
}
