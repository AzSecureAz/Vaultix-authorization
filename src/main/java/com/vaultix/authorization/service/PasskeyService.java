package com.vaultix.authorization.service;

import java.util.List;
import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.mfa.PasskeyResponse;
import com.vaultix.authorization.dto.mfa.UpdatePasskeyRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface PasskeyService {

    List<PasskeyResponse> getUserPasskeys(@NotNull(message = "User ID cannot be null") UUID userId);

    PasskeyResponse updatePasskeyLabel(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Passkey ID cannot be null") UUID passkeyId,
            @Valid @NotNull(message = "Update request cannot be null") UpdatePasskeyRequest request);

    void deletePasskey(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Passkey ID cannot be null") UUID passkeyId);
}
