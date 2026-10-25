package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.mfa.TotpActivationResponse;
import com.vaultix.authorization.service.TotpService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping({"/mfa/recovery-codes", "/recovery-codes"})
@RequiredArgsConstructor
public class MfaRecoveryCodeController {

    private final TotpService totpService;

    @GetMapping({"", "/", "/count"})
    public ResponseEntity<ApiResponse<Long>> getRemainingRecoveryCodes(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        long remaining = totpService.getRemainingRecoveryCodesCount(userId);
        return ResponseEntity.ok(ApiResponse.success("Remaining recovery codes count retrieved successfully.", remaining));
    }

    @PostMapping({"", "/", "/regenerate"})
    public ResponseEntity<ApiResponse<TotpActivationResponse>> regenerateRecoveryCodes(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        TotpActivationResponse response = totpService.regenerateRecoveryCodes(userId);
        return ResponseEntity.ok(ApiResponse.success(
                "Recovery codes regenerated successfully. Please store your new emergency recovery codes safely.",
                response));
    }
}
