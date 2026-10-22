package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.ValidUsername;

import jakarta.validation.constraints.NotBlank;

public record ChangeUsernameRequest(
        @NotBlank(message = "Username is required")
        @ValidUsername
        String username) {

}
