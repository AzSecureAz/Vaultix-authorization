package com.vaultix.authorization.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @Size(max = MAX_LENGTH, message = "Refresh token cannot exceed " + MAX_LENGTH + " characters")
        @JsonProperty("refresh_token")
        String refreshToken) {

    public static final int MAX_LENGTH = 4096;
}
