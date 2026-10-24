package com.vaultix.authorization.dto.mfa;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasskeyRequest(
        @NotBlank(message = "Passkey label is required")
        @Size(max = 128, message = "Passkey label cannot exceed 128 characters")
        String label) {

}
