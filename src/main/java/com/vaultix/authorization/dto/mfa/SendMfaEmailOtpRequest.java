package com.vaultix.authorization.dto.mfa;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SendMfaEmailOtpRequest(
        @NotBlank(message = "MFA challenge token is required")
        @Size(max = 128, message = "MFA challenge token cannot exceed 128 characters")
        String mfaToken) {

}
