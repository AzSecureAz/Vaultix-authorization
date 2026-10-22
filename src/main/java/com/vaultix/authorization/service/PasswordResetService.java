package com.vaultix.authorization.service;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.PasswordResetConfirmRequest;
import com.vaultix.authorization.dto.PasswordResetRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface PasswordResetService {

    void requestPasswordReset(
            @NotNull(message = "Password reset request cannot be null")
            @Valid PasswordResetRequest request);

    void confirmPasswordReset(
            @NotNull(message = "Password reset confirmation request cannot be null")
            @Valid PasswordResetConfirmRequest request);
}
