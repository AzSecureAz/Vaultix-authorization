package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.StrongPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Username or email is required")
        @Size(max = 256, message = "Identifier cannot exceed 256 characters")
        String identifier,
        @NotBlank(message = "Password is required")
        @Size(max = StrongPassword.MAX_LENGTH, message = "Password exceeds maximum allowed length")
        String password) {

}
