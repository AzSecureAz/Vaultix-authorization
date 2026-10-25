package com.vaultix.authorization.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.oauth2.google")
public record GoogleProperties(
        @NotBlank(message = "Google OAuth2 Client ID is required")
        @Size(max = 512, message = "Google OAuth2 Client ID cannot exceed 512 characters")
        @DefaultValue("YOUR_GOOGLE_CLIENT_ID")
        String clientId) {

}
