package com.vaultix.authorization.dto.oauth2;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record GitHubLoginRequest(
        @NotBlank(message = "GitHub authorization code cannot be blank")
        @Size(max = 256, message = "GitHub authorization code length cannot exceed 256 characters")
        String code,
        @Size(max = 1024, message = "Redirect URI length cannot exceed 1024 characters")
        String redirectUri) {

}
