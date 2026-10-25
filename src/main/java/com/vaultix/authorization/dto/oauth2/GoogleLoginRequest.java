package com.vaultix.authorization.dto.oauth2;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record GoogleLoginRequest(
        @NotBlank(message = "Google ID token cannot be blank")
        @Size(max = 8192, message = "Google ID token length cannot exceed 8192 characters")
        String idToken) {

}
