package com.vaultix.authorization.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RequestEmailChangeRequest(
        @NotBlank(message = "New email address is required")
        @Email(message = "Invalid email format")
        @Size(max = 256, message = "Email cannot exceed 256 characters")
        String newEmail) {

}
