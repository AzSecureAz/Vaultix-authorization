package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Validated
public interface TokenService {

    AuthResponse issueTokens(
            @NotNull(message = "User details cannot be null") CustomUserDetails userDetails,
            ClientContext clientContext);

    AuthResponse refreshTokens(
            @NotBlank(message = "Refresh token is required")
            @Size(max = RefreshTokenRequest.MAX_LENGTH, message = "Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters") String rawRefreshToken,
            ClientContext clientContext);

    void logout(
            @NotNull(message = "Access token JTI cannot be null") UUID accessTokenJti);

    int revokeAllUserTokens(@NotNull(message = "User ID cannot be null") UUID userId);

    int revokeOtherUserTokens(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Current access token JTI cannot be null") UUID currentAccessTokenJti);

    int cleanExpiredTokens();
}
