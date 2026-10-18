package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.lockout")
public record LockoutProperties(
        @Positive(message = "Max failed attempts must be greater than zero")
        @DefaultValue("5")
        int maxFailedAttempts,
        @NotNull(message = "Lockout duration is required")
        @DefaultValue("15m")
        Duration duration) {

}
