package com.vaultix.authorization.dto.mfa;

import com.vaultix.authorization.validation.ValidPasskeyLabel;

import jakarta.validation.constraints.NotBlank;

public record UpdatePasskeyRequest(
        @NotBlank(message = "Passkey label is required")
        @ValidPasskeyLabel
        String label) {

}
