package com.vaultix.authorization.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;

@Builder
public record AuthResponse(
        @JsonProperty("access_token")
        String accessToken,
        @JsonProperty("refresh_token")
        String refreshToken,
        @JsonProperty("token_type")
        String tokenType,
        @JsonProperty("expires_in")
        long expiresIn,
        @JsonProperty("must_change_password")
        boolean mustChangePassword,
        UserSummaryDto user) {

    public static final String TOKEN_TYPE_BEARER = "Bearer";
}
