package com.vaultix.authorization.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn,
        Boolean mfaRequired,
        String mfaToken,
        String maskedEmail,
        Boolean hasRecoveryCodes) {

    public static final String TOKEN_TYPE_BEARER = "Bearer";
}
