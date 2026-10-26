package com.vaultix.authorization.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.mfa.PasskeyResponse;
import com.vaultix.authorization.dto.mfa.UpdatePasskeyRequest;
import com.vaultix.authorization.service.PasskeyService;
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
@RequestMapping({"/mfa/passkeys", "/passkeys"})
@RequiredArgsConstructor
public class PasskeyController {

    private final PasskeyService passkeyService;

    @RequireSudo
    @GetMapping({"", "/"})
    public ResponseEntity<ApiResponse<List<PasskeyResponse>>> listPasskeys(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        List<PasskeyResponse> passkeys = passkeyService.getUserPasskeys(userId);
        return ResponseEntity.ok(ApiResponse.success("Passkeys retrieved successfully.", passkeys));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @RequestMapping(value = "/{id}", method = {RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.POST})
    public ResponseEntity<ApiResponse<PasskeyResponse>> updatePasskey(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @PathVariable("id") @NotNull(message = "Passkey ID is required") UUID id,
            @Valid @RequestBody UpdatePasskeyRequest request) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        PasskeyResponse response = passkeyService.updatePasskeyLabel(userId, id, request);
        return ResponseEntity.ok(ApiResponse.success("Passkey label updated successfully.", response));
    }

    @RequireSudo(maxAgeSeconds = 300)
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deletePasskey(
            @AuthenticationPrincipal @NotNull(message = "Authentication token is required") Jwt jwt,
            @PathVariable("id") @NotNull(message = "Passkey ID is required") UUID id) {

        UUID userId = SecurityUtil.extractActorId(jwt);
        passkeyService.deletePasskey(userId, id);
        return ResponseEntity.ok(ApiResponse.success("Passkey deleted successfully."));
    }
}
