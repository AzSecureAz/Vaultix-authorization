package com.vaultix.authorization.specification.request;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.vaultix.authorization.entity.enums.RoleStatus;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RoleSearchRequest(
        @Size(max = 64, message = "Search query cannot exceed 64 characters")
        String search,
        @Size(max = 100, message = "Cannot filter by more than 100 IDs at a time")
        Set<@NotNull(message = "Role ID cannot be null") UUID> ids,
        @Size(max = 100, message = "Cannot filter by more than 100 names at a time")
        Set<@NotBlank(message = "Role name cannot be blank")
        @Size(max = 64, message = "Role name cannot exceed 64 characters") String> names,
        Set<@NotNull(message = "Status cannot be null") RoleStatus> statuses,
        @Min(value = 0, message = "Minimum level cannot be negative")
        Integer minLevel,
        @Min(value = 0, message = "Maximum level cannot be negative")
        Integer maxLevel,
        @Size(max = 50, message = "Cannot filter by more than 50 permissions at a time")
        Set<@NotBlank(message = "Permission name cannot be blank")
        @Size(max = 128, message = "Permission name cannot exceed 128 characters") String> permissions,
        Instant createdAfter,
        Instant createdBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 creator IDs at a time")
        Set<@NotNull(message = "Created by ID cannot be null") UUID> createdBy,
        Instant updatedAfter,
        Instant updatedBefore,
        @Size(max = 100, message = "Cannot filter by more than 100 updater IDs at a time")
        Set<@NotNull(message = "Updated by ID cannot be null") UUID> updatedBy) {

}
