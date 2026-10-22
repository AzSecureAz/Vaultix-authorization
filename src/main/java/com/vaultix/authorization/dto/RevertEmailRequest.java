package com.vaultix.authorization.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RevertEmailRequest(
        @NotBlank(message = "Revert token is required")
        @Size(max = 128, message = "Revert token cannot exceed 128 characters")
        String token) {

}
