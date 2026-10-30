package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.SortDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.SessionResponse;
import com.vaultix.authorization.service.SessionService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping({"/sessions", "/auth/sessions"})
@RequiredArgsConstructor
public class SessionController {

    private final SessionService sessionService;

    @GetMapping("/current")
    public ResponseEntity<ApiResponse<SessionResponse>> getCurrentSession(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID currentAccessTokenJti = SecurityUtil.extractTokenId(jwt);
        SessionResponse currentSession = sessionService.getCurrentSession(currentAccessTokenJti);
        return ResponseEntity.ok(ApiResponse.success("Current session details", currentSession));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Page<SessionResponse>>> getOtherSessions(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @PageableDefault(size = 10)
            @SortDefault(sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        UUID currentAccessTokenJti = SecurityUtil.extractTokenId(jwt);

        Page<SessionResponse> sessions = sessionService.getOtherActiveSessions(userId, currentAccessTokenJti, pageable);
        return ResponseEntity.ok(ApiResponse.success("Other active sessions", sessions));
    }

    @DeleteMapping("/{sessionId:[0-9a-fA-F\\-]{36}}")
    public ResponseEntity<ApiResponse<Void>> revokeSession(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @PathVariable UUID sessionId) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        sessionService.revokeSession(userId, sessionId);
        return ResponseEntity.ok(ApiResponse.success("Session revoked successfully"));
    }

    @DeleteMapping("/other")
    public ResponseEntity<ApiResponse<Void>> revokeOtherSessions(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        UUID currentAccessTokenJti = SecurityUtil.extractTokenId(jwt);
        sessionService.revokeOtherSessions(userId, currentAccessTokenJti);
        return ResponseEntity.ok(ApiResponse.success("Revoked all other active sessions successfully"));
    }

    @DeleteMapping
    public ResponseEntity<ApiResponse<Void>> revokeAllSessions(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        sessionService.revokeAllSessions(userId);
        return ResponseEntity.ok(ApiResponse.success("Revoked all active sessions successfully"));
    }
}
