package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.StrongPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetConfirmRequest(
        @NotBlank(message = "Username or email is required")
        @Size(max = 256, message = "Identifier cannot exceed 256 characters")
        String identifier,
        @NotBlank(message = "OTP is required")
        @Size(min = 4, max = 10, message = "Invalid OTP length")
        String otp,
        @NotBlank(message = "New password is required")
        @StrongPassword
        String newPassword) {

}
