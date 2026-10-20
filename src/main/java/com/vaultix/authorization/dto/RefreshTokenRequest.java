package com.vaultix.authorization.dto;

import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @Size(max = MAX_LENGTH, message = "Refresh token cannot exceed " + MAX_LENGTH + " characters")
        String refreshToken) {

    public static final int MAX_LENGTH = 4096;
}
