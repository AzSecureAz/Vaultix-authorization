package com.vaultix.authorization.dto.admin;

import java.util.Set;

import com.vaultix.authorization.validation.ValidRoleName;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreateRoleRequest(
        @NotBlank(message = "Role name is required")
        @ValidRoleName
        String name,
        @Size(max = 256, message = "Description cannot exceed 256 characters")
        String description,
        @NotNull(message = "Role level is required")
        @Min(value = 1, message = "Role level must be greater than 0")
        Integer level,
        Set<@NotBlank(message = "Permission name cannot be blank")
        @Size(max = 128, message = "Permission name cannot exceed 128 characters") String> permissions) {

}
