package com.vaultix.authorization.dto.admin;

import java.util.Set;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateRoleRequest(
        @Size(max = 256, message = "Description cannot exceed 256 characters")
        String description,
        @Min(value = 1, message = "Role level must be greater than 0")
        Integer level,
        Set<@NotBlank(message = "Permission name cannot be blank")
        @Size(max = 128, message = "Permission name cannot exceed 128 characters") String> permissions) {

}
