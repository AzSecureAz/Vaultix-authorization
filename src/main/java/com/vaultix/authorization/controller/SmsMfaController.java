package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.mfa.SmsMfaActivationResponse;
import com.vaultix.authorization.dto.mfa.VerifySmsMfaRequest;
import com.vaultix.authorization.service.SmsMfaService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.RequireSudo;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping({"/mfa/sms", "/sms-mfa"})
@RequiredArgsConstructor
public class SmsMfaController {

    private final SmsMfaService smsMfaService;

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping({"/setup", "/send-setup-otp", "/initiate"})
    public ResponseEntity<ApiResponse<Void>> sendSetupOtp(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        smsMfaService.sendSetupOtp(userId);
        return ResponseEntity.ok(ApiResponse.success("Verification code sent to your registered phone number."));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping({"/enable", "/activate", "/verify"})
    public ResponseEntity<ApiResponse<SmsMfaActivationResponse>> enableSmsMfa(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody VerifySmsMfaRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        SmsMfaActivationResponse response = smsMfaService.enableSmsMfa(userId, request);
        return ResponseEntity.ok(ApiResponse.success(
                "SMS two-factor authentication enabled successfully.",
                response));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<Void>> disableSmsMfa(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        smsMfaService.disableSmsMfa(userId);
        return ResponseEntity.ok(ApiResponse.success("SMS two-factor authentication has been disabled successfully."));
    }
}
