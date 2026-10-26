package com.vaultix.authorization.dto;

import com.vaultix.authorization.validation.ValidFullName;

import jakarta.validation.constraints.NotBlank;

public record UpdateFullNameRequest(
        @NotBlank(message = "Full name is required")
        @ValidFullName
        String fullName) {

}
