package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.jwt")
public record JwtProperties(
        @NotBlank(message = "Token issuer is required")
        @DefaultValue("https://auth.vaultix.com")
        String issuer,
        @NotNull(message = "Access token expiration duration is required")
        @DefaultValue("5m")
        Duration accessTokenExpiration,
        @NotNull(message = "Refresh token expiration duration is required")
        @DefaultValue("7d")
        Duration refreshTokenExpiration) {

}
