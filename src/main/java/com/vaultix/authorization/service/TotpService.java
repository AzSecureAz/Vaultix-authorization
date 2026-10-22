package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.mfa.DisableTotpRequest;
import com.vaultix.authorization.dto.mfa.TotpActivationResponse;
import com.vaultix.authorization.dto.mfa.TotpSetupResponse;
import com.vaultix.authorization.dto.mfa.VerifyTotpRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface TotpService {

    TotpSetupResponse initiateSetup(@NotNull(message = "User ID cannot be null") UUID userId);

    TotpActivationResponse activateTotp(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @Valid @NotNull(message = "Verification request cannot be null") VerifyTotpRequest request);

    void disableTotp(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @Valid @NotNull(message = "Disable request cannot be null") DisableTotpRequest request);
}
