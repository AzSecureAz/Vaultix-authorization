package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.StrongPassword;
import com.vaultix.authorization.validation.ValidUsername;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Username is required")
        @ValidUsername
        String username,
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @Size(max = 256, message = "Email cannot exceed 256 characters")
        String email,
        @NotBlank(message = "Password is required")
        @StrongPassword
        String password,
        @Size(max = 256, message = "Full name cannot exceed 256 characters")
        String fullName,
        @Size(max = 32, message = "Phone number cannot exceed 32 characters")
        String phoneNumber) {

}
