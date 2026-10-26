package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.mfa.RecoveryCodesResponse;
import com.vaultix.authorization.dto.mfa.TotpActivationResponse;
import com.vaultix.authorization.dto.mfa.TotpSetupResponse;
import com.vaultix.authorization.dto.mfa.VerifyTotpRequest;
import com.vaultix.authorization.service.TotpService;
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
@RequestMapping({"/mfa/totp", "/totp"})
@RequiredArgsConstructor
public class TotpController {

    private final TotpService totpService;

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping({"/setup", "/initiate"})
    public ResponseEntity<ApiResponse<TotpSetupResponse>> setupTotp(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        TotpSetupResponse response = totpService.initiateSetup(userId);
        return ResponseEntity.ok(ApiResponse.success("TOTP setup initiated. Scan the QR code or enter the key manually.", response));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping({"/activate", "/verify"})
    public ResponseEntity<ApiResponse<TotpActivationResponse>> activateTotp(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody VerifyTotpRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        TotpActivationResponse response = totpService.activateTotp(userId, request);
        return ResponseEntity.ok(ApiResponse.success(
                "TOTP two-factor authentication activated successfully. Please store your emergency recovery codes safely.",
                response));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<Void>> disableTotp(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        totpService.disableTotp(userId);
        return ResponseEntity.ok(ApiResponse.success("TOTP two-factor authentication has been disabled successfully."));
    }

    @GetMapping({"/recovery-codes", "/recovery-codes/count"})
    public ResponseEntity<ApiResponse<Long>> getRemainingRecoveryCodes(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        long remaining = totpService.getRemainingRecoveryCodesCount(userId);
        return ResponseEntity.ok(ApiResponse.success("Remaining recovery codes count retrieved successfully.", remaining));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @PostMapping({"/recovery-codes/regenerate", "/recovery-codes"})
    public ResponseEntity<ApiResponse<RecoveryCodesResponse>> regenerateRecoveryCodes(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        RecoveryCodesResponse response = totpService.regenerateRecoveryCodes(userId);
        return ResponseEntity.ok(ApiResponse.success(
                "Recovery codes regenerated successfully. Please store your new emergency recovery codes safely.",
                response));
    }
}
