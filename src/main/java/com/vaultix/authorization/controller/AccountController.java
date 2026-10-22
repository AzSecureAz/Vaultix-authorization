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
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;
    private final AuthCookieHelper authCookieHelper;

    @GetMapping({"/me", "/profile"})
    public ResponseEntity<ApiResponse<UserProfileDto>> getMe(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        UserProfileDto profile = accountService.getProfile(userId);
        return ResponseEntity.ok(ApiResponse.success("Current user profile", profile));
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

    @PostMapping({"/password/change", "/password-change"})
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.changePassword(userId, request);

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Password changed successfully. Please log in with your new password."));
    }

    @PostMapping({"/email/send-verification", "/email/send/verification", "/email/verification/send"})
    public ResponseEntity<ApiResponse<Void>> sendEmailVerification(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.sendEmailVerification(userId);
        return ResponseEntity.ok(ApiResponse.success("Verification code sent to your email address"));
    }

    @PostMapping({"/email/verify", "/email-verify"})
    public ResponseEntity<ApiResponse<Void>> verifyEmail(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody VerifyEmailRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.verifyEmail(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Email verified successfully"));
    }
}
