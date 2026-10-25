package com.vaultix.authorization.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Validated
@ConfigurationProperties(prefix = "vaultix.oauth2.github")
public record GitHubProperties(
        @NotBlank(message = "GitHub OAuth2 Client ID is required")
        @Size(max = 512, message = "GitHub OAuth2 Client ID cannot exceed 512 characters")
        @DefaultValue("YOUR_GITHUB_CLIENT_ID")
        String clientId,
        @NotBlank(message = "GitHub OAuth2 Client Secret is required")
        @Size(max = 512, message = "GitHub OAuth2 Client Secret cannot exceed 512 characters")
        @DefaultValue("YOUR_GITHUB_CLIENT_SECRET")
        String clientSecret,
        @Size(max = 1024, message = "GitHub OAuth2 Redirect URI cannot exceed 1024 characters")
        @DefaultValue("")
        String redirectUri) {

}
