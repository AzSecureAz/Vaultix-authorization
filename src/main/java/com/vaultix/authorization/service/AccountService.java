package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface AccountService {

    UserProfileDto getProfile(@NotNull(message = "User ID cannot be null") UUID userId);

    void changeUsername(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change username request cannot be null")
            @Valid ChangeUsernameRequest request);

    void changePassword(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change password request cannot be null")
            @Valid ChangePasswordRequest request);

    void sendEmailVerification(@NotNull(message = "User ID cannot be null") UUID userId);

    void verifyEmail(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Verification request cannot be null")
            @Valid VerifyEmailRequest request);
}
