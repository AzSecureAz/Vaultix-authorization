package com.vaultix.authorization.dto;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SudoResponse(
        boolean elevated,
        long expiresInSeconds,
        Instant expiresAt) {

    public static SudoResponse active(long expiresInSeconds) {
        return new SudoResponse(true, expiresInSeconds, Instant.now().plusSeconds(expiresInSeconds));
    }

    public static SudoResponse inactive() {
        return new SudoResponse(false, 0, null);
    }
}
