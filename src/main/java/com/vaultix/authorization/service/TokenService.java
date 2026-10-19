package com.vaultix.authorization.service;

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
            @NotBlank(message = "Access token JTI is required")
            @Size(max = 64, message = "Access token JTI cannot exceed 64 characters") String accessTokenJti);

    int cleanExpiredTokens();
}
