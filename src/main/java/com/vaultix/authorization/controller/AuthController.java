package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthCookieHelper authCookieHelper;

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            HttpServletRequest httpRequest) {

        if (jwt.getId() != null && !jwt.getId().isBlank()) {
            try {
                authService.logout(UUID.fromString(jwt.getId().strip()));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid UUID format for access token JTI during logout: {}", jwt.getId());
            }
        }

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Logged out successfully"));
    }

    @PostMapping({"/logout-other", "/logout/other"})
    public ResponseEntity<ApiResponse<Void>> logoutOther(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        UUID currentAccessTokenJti = null;
        if (jwt.getId() != null && !jwt.getId().isBlank()) {
            try {
                currentAccessTokenJti = UUID.fromString(jwt.getId().strip());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid UUID format for current access token JTI during logout other: {}", jwt.getId());
            }
        }

        if (currentAccessTokenJti == null) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Valid session token identifier is required"));
        }

        authService.logoutOther(userId, currentAccessTokenJti);

        return ResponseEntity.ok(ApiResponse.success("Logged out from all other devices successfully"));
    }

    @PostMapping({"/logout-all", "/logout/all"})
    public ResponseEntity<ApiResponse<Void>> logoutAll(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            HttpServletRequest httpRequest) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        authService.logoutAll(userId);

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Logged out from all devices successfully"));
    }
}
