package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

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
        Duration refreshTokenExpiration,
        @NotBlank(message = "Key rotation cron expression is required")
        @DefaultValue("0 0 2 * * ?")
        String keyRotationCron,
        @NotBlank(message = "Key cleanup cron expression is required")
        @DefaultValue("0 10 2 * * ?")
        String keyCleanupCron,
        @NotNull(message = "Key cleanup grace period is required")
        @DefaultValue("7d")
        Duration keyCleanupGracePeriod,
        @Positive(message = "Key cleanup batch size must be positive")
        @DefaultValue("100")
        int keyCleanupBatchSize) {

}
