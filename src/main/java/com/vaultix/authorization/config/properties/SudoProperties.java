package com.vaultix.authorization.config.properties;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.sudo")
public record SudoProperties(
        @NotNull(message = "Sudo duration is required")
        @DefaultValue("30m")
        Duration duration) {

}
