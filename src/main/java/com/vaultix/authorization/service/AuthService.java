package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.PasswordResetConfirmRequest;
import com.vaultix.authorization.dto.PasswordResetRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Validated
public interface AuthService {

    AuthResponse login(
            @NotNull(message = "Login request cannot be null")
            @Valid LoginRequest request,
            ClientContext clientContext);

    AuthResponse refreshToken(
            @NotBlank(message = "Refresh token is required")
            @Size(max = RefreshTokenRequest.MAX_LENGTH, message = "Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters") String rawRefreshToken,
            ClientContext clientContext);

    void logout(
            @NotBlank(message = "Access token JTI is required")
            @Size(max = 64, message = "Access token JTI cannot exceed 64 characters") String accessTokenJti);

    int logoutAll(@NotNull(message = "User ID cannot be null") UUID userId);

    UserProfileDto getProfile(@NotNull(message = "User ID cannot be null") UUID userId);

    void requestPasswordReset(
            @NotNull(message = "Password reset request cannot be null")
            @Valid PasswordResetRequest request);

    void confirmPasswordReset(
            @NotNull(message = "Password reset confirmation request cannot be null")
            @Valid PasswordResetConfirmRequest request);

    void sendEmailVerification(@NotNull(message = "User ID cannot be null") UUID userId);

    void verifyEmail(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Verification request cannot be null")
            @Valid VerifyEmailRequest request);
}
