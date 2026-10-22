package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.service.AccountService;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AccountService accountService;
    private final AuthCookieHelper authCookieHelper;

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            HttpServletRequest httpRequest) {

        if (jwt.getId() != null && !jwt.getId().isBlank()) {
            authService.logout(jwt.getId().strip());
        }

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Logged out successfully"));
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

    @GetMapping({"/me", "/profile"})
    public ResponseEntity<ApiResponse<UserProfileDto>> getMe(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        UserProfileDto profile = authService.getProfile(userId);
        return ResponseEntity.ok(ApiResponse.success("Current user profile", profile));
    }

    @PostMapping({"/email/send-verification", "/email/send/verification", "/email/verification/send"})
    public ResponseEntity<ApiResponse<Void>> sendEmailVerification(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        authService.sendEmailVerification(userId);
        return ResponseEntity.ok(ApiResponse.success("Verification code sent to your email address"));
    }

    @PostMapping({"/email/verify", "/email-verify"})
    public ResponseEntity<ApiResponse<Void>> verifyEmail(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody VerifyEmailRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        authService.verifyEmail(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Email verified successfully"));
    }

    @PostMapping({"/password/change", "/password-change"})
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        authService.changePassword(userId, request);

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Password changed successfully. Please log in with your new password."));
    }

    @PutMapping({"/username", "/username/change"})
    public ResponseEntity<ApiResponse<Void>> changeUsername(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody ChangeUsernameRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.changeUsername(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Username changed successfully"));
    }

    @PostMapping({"/username/change", "/username-change"})
    public ResponseEntity<ApiResponse<Void>> changeUsernamePost(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody ChangeUsernameRequest request) {

        return changeUsername(jwt, request);
    }
}
