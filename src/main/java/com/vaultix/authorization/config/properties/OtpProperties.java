package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.otp")
public record OtpProperties(
        @Min(value = 4, message = "OTP length must be at least 4 digits")
        @Max(value = 8, message = "OTP length cannot exceed 8 digits")
        @DefaultValue("6")
        int length,
        @NotNull(message = "Default OTP TTL is required")
        @DefaultValue("10m")
        Duration defaultTtl,
        @Positive(message = "Max attempts must be positive")
        @DefaultValue("5")
        int maxAttempts) {

}
