package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.mfa.SmsMfaActivationResponse;
import com.vaultix.authorization.dto.mfa.VerifySmsMfaRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface SmsMfaService {

    void sendSetupOtp(@NotNull(message = "User ID cannot be null") UUID userId);

    SmsMfaActivationResponse enableSmsMfa(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @Valid @NotNull(message = "Verification request cannot be null") VerifySmsMfaRequest request);

    void disableSmsMfa(@NotNull(message = "User ID cannot be null") UUID userId);

    void sendLoginSmsOtp(@NotNull(message = "User ID cannot be null") UUID userId);
}
