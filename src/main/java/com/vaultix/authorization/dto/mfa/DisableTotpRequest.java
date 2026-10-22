package com.vaultix.authorization.dto.mfa;

import com.vaultix.authorization.validation.StrongPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DisableTotpRequest(
        @NotBlank(message = "Current password is required")
        @Size(max = StrongPassword.MAX_LENGTH, message = "Current password cannot exceed " + StrongPassword.MAX_LENGTH + " characters")
        String currentPassword) {

}
