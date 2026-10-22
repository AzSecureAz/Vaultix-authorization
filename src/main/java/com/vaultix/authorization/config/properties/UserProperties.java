package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.user")
public record UserProperties(
        @NotBlank(message = "User cleanup cron expression is required")
        @DefaultValue("0 40 2 * * ?")
        String cleanupCron,
        @NotNull(message = "User cleanup grace period is required")
        @DefaultValue("90d")
        Duration cleanupGracePeriod,
        @Positive(message = "User cleanup batch size must be positive")
        @DefaultValue("100")
        int cleanupBatchSize) {

}
