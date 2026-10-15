package com.vaultix.authorization.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @Size(max = MAX_LENGTH, message = "Refresh token exceeds maximum allowed length")
        @JsonProperty("refresh_token")
        String refreshToken) {

    public static final int MAX_LENGTH = 4096;
}
