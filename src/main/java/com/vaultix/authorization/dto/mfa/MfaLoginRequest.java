package com.vaultix.authorization.dto.mfa;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MfaLoginRequest(
        @NotBlank(message = "MFA challenge token is required")
        @Size(max = 128, message = "MFA challenge token cannot exceed 128 characters")
        String mfaToken,
        @NotBlank(message = "Verification code is required")
        @Size(max = 64, message = "Verification code cannot exceed 64 characters")
        String code,
        @Size(max = 32, message = "MFA factor cannot exceed 32 characters")
        String factor) {

}
