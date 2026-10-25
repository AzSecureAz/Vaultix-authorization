package com.vaultix.authorization.dto.mfa;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifySmsMfaRequest(
        @NotBlank(message = "SMS verification code is required")
        @Pattern(regexp = "^\\d{6}$", message = "SMS verification code must be a 6-digit number")
        String code) {

}
