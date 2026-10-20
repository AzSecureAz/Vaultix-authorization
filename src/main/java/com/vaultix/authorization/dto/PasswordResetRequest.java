package com.vaultix.authorization.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(
        @NotBlank(message = "Username or email is required")
        @Size(max = 256, message = "Identifier cannot exceed 256 characters")
        String identifier) {

}
