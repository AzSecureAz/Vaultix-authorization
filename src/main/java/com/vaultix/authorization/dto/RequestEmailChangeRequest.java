package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.StrongPassword;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RequestEmailChangeRequest(
        @NotBlank(message = "New email address is required")
        @Email(message = "Invalid email format")
        @Size(max = 256, message = "Email cannot exceed 256 characters")
        String newEmail,
        @NotBlank(message = "Current password is required")
        @Size(max = StrongPassword.MAX_LENGTH, message = "Current password cannot exceed " + StrongPassword.MAX_LENGTH + " characters")
        String currentPassword) {

}
