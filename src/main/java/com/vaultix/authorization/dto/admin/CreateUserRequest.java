package com.vaultix.authorization.dto.admin;

import java.util.Set;

import com.vaultix.authorization.validation.ValidFullName;
import com.vaultix.authorization.validation.ValidUsername;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
        @NotBlank(message = "Username is required")
        @ValidUsername
        String username,
        @NotBlank(message = "Email is required")
        @Email(message = "Must be a valid email address")
        @Size(max = 256, message = "Email cannot exceed 256 characters")
        String email,
        @ValidFullName
        String fullName,
        Set<@NotBlank(message = "Role name cannot be blank")
        @Size(max = 64, message = "Role name cannot exceed 64 characters") String> roles) {

}
