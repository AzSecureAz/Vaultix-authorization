package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.ConfirmEmailChangeRequest;
import com.vaultix.authorization.dto.RequestEmailChangeRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.authorization.dto.VerifyPhoneNumberRequest;
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
@Validated
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

    @RequestMapping(value = {"/username", "/username/change", "/username-change"}, method = {RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.POST})
    public ResponseEntity<ApiResponse<Void>> changeUsername(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody ChangeUsernameRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.changeUsername(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Username changed successfully"));
    }

    @RequestMapping(value = {"/password", "/password/change", "/password-change"}, method = {RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.POST})
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

    @PostMapping({"/phone/send-verification", "/phone/send/verification", "/phone/verification/send"})
    public ResponseEntity<ApiResponse<Void>> sendPhoneNumberVerification(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.sendPhoneNumberVerification(userId);
        return ResponseEntity.ok(ApiResponse.success("Verification code sent to your phone number"));
    }

    @PostMapping({"/phone/verify", "/phone-verify"})
    public ResponseEntity<ApiResponse<Void>> verifyPhoneNumber(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody VerifyPhoneNumberRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.verifyPhoneNumber(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Phone number verified successfully"));
    }

    @RequestMapping(value = {"/email/change/request", "/email/change-request", "/email/request-change", "/email/change"}, method = {RequestMethod.POST, RequestMethod.PUT})
    public ResponseEntity<ApiResponse<Void>> requestEmailChange(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody RequestEmailChangeRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.requestEmailChange(userId, request);
        return ResponseEntity.ok(ApiResponse.success("Verification code sent to your new email address. Please enter the code to complete the email change."));
    }

    @PostMapping({"/email/change/confirm", "/email/confirm-change", "/email/change-confirm"})
    public ResponseEntity<ApiResponse<Void>> confirmEmailChange(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody ConfirmEmailChangeRequest request,
            HttpServletRequest httpRequest) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        accountService.confirmEmailChange(userId, request);

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Email changed successfully. Please log in with your new email address."));
    }
}
