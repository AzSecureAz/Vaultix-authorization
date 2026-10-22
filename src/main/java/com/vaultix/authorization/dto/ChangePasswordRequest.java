package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.StrongPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank(message = "Current password is required")
        @Size(max = StrongPassword.MAX_LENGTH, message = "Current password cannot exceed " + StrongPassword.MAX_LENGTH + " characters")
        String currentPassword,
        @NotBlank(message = "New password is required")
        @StrongPassword
        String newPassword) {

}
