package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.role")
public record RoleProperties(
        @NotBlank(message = "Role cleanup cron expression is required")
        @DefaultValue("0 30 2 * * ?")
        String cleanupCron,
        @NotNull(message = "Role cleanup grace period is required")
        @DefaultValue("30d")
        Duration cleanupGracePeriod,
        @Positive(message = "Role cleanup batch size must be positive")
        @DefaultValue("100")
        int cleanupBatchSize) {

}
