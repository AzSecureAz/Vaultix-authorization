package com.vaultix.authorization.dto.mfa;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyTotpRequest(
        @NotBlank(message = "TOTP code is required")
        @Pattern(regexp = "^\\d{6}$", message = "TOTP code must be a 6-digit number")
        String code) {

}
