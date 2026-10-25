package com.vaultix.authorization.controller;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.SudoResponse;
import com.vaultix.authorization.dto.SudoVerifyRequest;
import com.vaultix.authorization.service.AuthSudoService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;
import com.vaultix.common.util.ClientContextUtil;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/sudo")
@RequiredArgsConstructor
public class SudoController {

    private final AuthSudoService authSudoService;

    @GetMapping({"", "/", "/status"})
    public ResponseEntity<ApiResponse<SudoResponse>> getSudoStatus(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID sessionId = SecurityUtil.extractSessionId(jwt);
        SudoResponse response = authSudoService.getStatus(sessionId);
        return ResponseEntity.ok(ApiResponse.success("Sudo status retrieved successfully", response));
    }

    @PostMapping({"", "/", "/verify"})
    public ResponseEntity<ApiResponse<SudoResponse>> verifySudo(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @Valid @RequestBody SudoVerifyRequest request,
            HttpServletRequest httpRequest) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        UUID sessionId = SecurityUtil.extractSessionId(jwt);
        ClientContext clientContext = ClientContextUtil.extract(httpRequest);

        log.info("Received sudo verification request for user ID: {}, session ID: {}", userId, sessionId);
        SudoResponse response = authSudoService.verifySudo(userId, sessionId, request, clientContext);
        return ResponseEntity.ok(ApiResponse.success("Sudo elevation activated successfully", response));
    }

    @PostMapping({"/send-sms-otp", "/sms-otp"})
    public ResponseEntity<ApiResponse<Void>> sendSudoSmsOtp(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        authSudoService.sendSudoSmsOtp(userId);
        return ResponseEntity.ok(ApiResponse.success("Verification code sent to your registered phone number"));
    }

    @DeleteMapping({"", "/", "/revoke"})
    @PostMapping("/revoke")
    public ResponseEntity<ApiResponse<Void>> revokeSudo(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID sessionId = SecurityUtil.extractSessionId(jwt);
        authSudoService.revokeSudo(sessionId);
        return ResponseEntity.ok(ApiResponse.success("Sudo mode revoked successfully"));
    }
}
