package com.vaultix.authorization.config.properties;

import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.security.passkey")
public record PasskeyProperties(
        @NotBlank(message = "Relying Party ID is required")
        @Size(max = 256, message = "Relying Party ID cannot exceed 256 characters")
        @DefaultValue("localhost")
        String rpId,
        @NotBlank(message = "Relying Party Name is required")
        @Size(max = 128, message = "Relying Party Name cannot exceed 128 characters")
        @DefaultValue("Vaultix")
        String rpName,
        @NotEmpty(message = "At least one allowed origin must be specified")
        @DefaultValue({"http://localhost:3000", "http://localhost:5173", "http://localhost:8080"})
        Set<@NotBlank(message = "Allowed origin cannot be blank")
        @Size(max = 1024, message = "Allowed origin cannot exceed 1024 characters") String> allowedOrigins) {

}
