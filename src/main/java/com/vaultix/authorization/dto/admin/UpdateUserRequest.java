package com.vaultix.authorization.dto.admin;

import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        Set<@NotBlank(message = "Role name cannot be blank")
        @Size(max = 64, message = "Role name cannot exceed 64 characters") String> roles) {

}
